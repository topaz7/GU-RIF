#!/usr/bin/env python3
"""
inspect_project.py
------------------
Read-only reconnaissance of the Gulu RIF-MIS codebase.

Run from the project root:
    python inspect_project.py
    python inspect_project.py --out report.txt

It does NOT modify anything. It walks the tree, parses Python with `ast`
(so imports/classes/functions are read statically, no execution), and
summarises templates, static assets, config and dependencies.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "node_modules", "venv", ".venv", "env", ".env",
    "dist", "build", "*.egg-info", ".idea", ".vscode", "migrations/versions",
}

CODE_EXTS = {
    ".py", ".html", ".jinja", ".jinja2", ".js", ".ts", ".css", ".scss",
    ".sql", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env",
    ".md", ".txt", ".sh",
}

MAX_FILE_BYTES = 400_000  # skip anything larger (probably data/binary)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def is_ignored(path: Path) -> bool:
    return any(part in IGNORE_DIRS for part in path.parts)


def read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def header(title: str) -> str:
    bar = "=" * 78
    return f"\n{bar}\n{title}\n{bar}\n"


def sub(title: str) -> str:
    return f"\n--- {title} " + "-" * max(0, 74 - len(title)) + "\n"


# --------------------------------------------------------------------------
# Data collectors
# --------------------------------------------------------------------------

@dataclass
class PyModuleInfo:
    path: Path
    rel: str
    docstring: str = ""
    imports: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    has_type_hints: bool = False
    lineno: int = 0
    error: str = ""


def parse_python(path: Path, rel: str) -> PyModuleInfo:
    info = PyModuleInfo(path=path, rel=rel)
    src = read_text(path)
    if not src:
        info.error = "empty or unreadable"
        return info
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        info.error = f"SyntaxError line {e.lineno}: {e.msg}"
        return info

    info.lineno = src.count("\n") + 1
    info.docstring = (ast.get_docstring(tree) or "").strip().splitlines()[0] if ast.get_docstring(tree) else ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                info.imports.append(n.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for n in node.names:
                info.imports.append(f"{mod}.{n.name}" if mod else n.name)
        elif isinstance(node, ast.ClassDef):
            info.classes.append(node.name)
            if node.decorator_list:
                for d in node.decorator_list:
                    info.decorators.append(_deco_name(d))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info.functions.append(node.name)
            for d in node.decorator_list:
                info.decorators.append(_deco_name(d))
            # crude type-hint check on args / return
            if node.returns is not None or any(a.annotation for a in node.args.args):
                info.has_type_hints = True
    return info


def _deco_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_deco_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _deco_name(node.func)
    return "?"


# --------------------------------------------------------------------------
# Analysers
# --------------------------------------------------------------------------

def walk_tree(root: Path) -> tuple[list[Path], dict[str, int]]:
    files: list[Path] = []
    by_ext: Counter[str] = Counter()
    for dirpath, dirnames, filenames in os.walk(root):
        p = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for f in filenames:
            fp = p / f
            if is_ignored(fp):
                continue
            files.append(fp)
            by_ext[fp.suffix.lower() or "<noext>"] += 1
    return files, dict(by_ext)


def render_tree(root: Path, max_depth: int = 4) -> str:
    lines: list[str] = []

    def rec(d: Path, prefix: str, depth: int):
        if depth > max_depth:
            return
        try:
            entries = sorted(
                [e for e in d.iterdir() if e.name not in IGNORE_DIRS and not e.name.startswith(".")],
                key=lambda e: (e.is_file(), e.name.lower()),
            )
        except OSError:
            return
        for i, e in enumerate(entries):
            last = i == len(entries) - 1
            branch = "└── " if last else "├── "
            lines.append(prefix + branch + e.name + ("/" if e.is_dir() else ""))
            if e.is_dir():
                rec(e, prefix + ("    " if last else "│   "), depth + 1)

    lines.append(root.name + "/")
    rec(root, "", 1)
    return "\n".join(lines)


def summarise_python(files: list[Path], root: Path) -> list[PyModuleInfo]:
    out: list[PyModuleInfo] = []
    for f in files:
        if f.suffix == ".py":
            out.append(parse_python(f, str(f.relative_to(root))))
    return out


def detect_flask_patterns(py_mods: list[PyModuleInfo]) -> dict:
    result = {
        "has_app_factory": False,
        "app_factory_line": "",
        "blueprints": [],          # (name, module, url_prefix?)
        "extensions": defaultdict(list),
        "route_decorators": [],
        "before_request": [],
        "error_handlers": [],
    }
    for m in py_mods:
        src = read_text(m.path)
        if re.search(r"def\s+create_app\s*\(", src):
            result["has_app_factory"] = True
            # capture the def line
            for i, line in enumerate(src.splitlines(), 1):
                if "def create_app" in line:
                    result["app_factory_line"] = f"{m.rel}:{i}: {line.strip()}"
                    break
        # blueprints
        for match in re.finditer(
            r"(\w+)\s*=\s*Blueprint\(\s*['\"]([^'\"]+)['\"]"
            r"(?:\s*,\s*__name__[^)]*)?(?:,\s*url_prefix\s*=\s*['\"]([^'\"]*)['\"])?",
            src,
        ):
            result["blueprints"].append((match.group(2), m.rel, match.group(3) or ""))
        # extensions init (db = SQLAlchemy(), login_manager = LoginManager(), etc.)
        for match in re.finditer(r"^(\w+)\s*=\s*([A-Z]\w+)\(", src, re.MULTILINE):
            result["extensions"][match.group(2)].append(f"{m.rel}:{match.group(1)}")
        # routes
        for match in re.finditer(
            r"@(\w+)\.route\(\s*['\"]([^'\"]+)['\"]([^)]*)\)", src
        ):
            methods = re.findall(r"methods\s*=\s*\[([^\]]*)\]", match.group(3))
            methods_s = methods[0].replace("'", "").replace('"', "") if methods else "GET"
            result["route_decorators"].append(
                (m.rel, match.group(2), methods_s.strip())
            )
        # before_request / errorhandler
        for match in re.finditer(r"@(\w+)\.before_request", src):
            result["before_request"].append((m.rel, match.group(1)))
        for match in re.finditer(r"@(\w+)\.errorhandler\(\s*(\d+)\s*\)", src):
            result["error_handlers"].append((m.rel, match.group(2)))
    return result


def analyse_models(py_mods: list[PyModuleInfo]) -> list[tuple[str, list[tuple[str, str]]]]:
    """Return [(module, [(ClassName, 'table=.., fields=[...]')])] for SQLAlchemy models."""
    out = []
    for m in py_mods:
        src = read_text(m.path)
        if "db.Model" not in src and "declarative_base" not in src:
            continue
        classes: list[tuple[str, str]] = []
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [_deco_name(b) for b in node.bases]
            if not any("Model" in b or "Base" in b for b in bases):
                continue
            fields = []
            tablename = ""
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for t in item.targets:
                        if isinstance(t, ast.Name):
                            if t.id == "__tablename__" and isinstance(item.value, ast.Constant):
                                tablename = str(item.value.value)
                            else:
                                fields.append(t.id)
            classes.append((node.name, f"table={tablename or '? '} fields=[{', '.join(fields[:12])}{'...' if len(fields) > 12 else ''}]"))
        if classes:
            out.append((m.rel, classes))
    return out


def analyse_templates(files: list[Path], root: Path) -> dict:
    tpls = [f for f in files if f.suffix.lower() in {".html", ".jinja", ".jinja2"}]
    info = {
        "count": len(tpls),
        "by_dir": Counter(),
        "extends": [],       # (file, parent)
        "blocks": defaultdict(list),
        "includes": [],
        "forms_or_csrf": [],
        "bootstrap": Counter(),
        "uses_url_for": 0,
        "uses_flash": 0,
        "files": [],
    }
    for t in tpls:
        rel = str(t.relative_to(root))
        info["by_dir"][str(t.parent.relative_to(root)) if t.parent != root else "."] += 1
        info["files"].append(rel)
        src = read_text(t)
        m = re.search(r"{%\s*extends\s*['\"]([^'\"]+)['\"]\s*%}", src)
        if m:
            info["extends"].append((rel, m.group(1)))
        for b in re.findall(r"{%\s*block\s+(\w+)", src):
            info["blocks"][rel].append(b)
        for i in re.findall(r"{%\s*include\s*['\"]([^'\"]+)['\"]", src):
            info["includes"].append((rel, i))
        if "csrf_token" in src or "csrf" in src.lower():
            info["forms_or_csrf"].append(rel)
        for cls in re.findall(r'class="([^"]+)"', src):
            for token in cls.split():
                if token.startswith(("btn-", "form-", "container", "row", "col-", "card", "navbar", "alert", "nav-", "table")):
                    info["bootstrap"][token] += 1
        if "url_for(" in src:
            info["uses_url_for"] += 1
        if "get_flashed_messages" in src or "flash(" in src:
            info["uses_flash"] += 1
    return info


def analyse_config(files: list[Path], root: Path) -> dict:
    out = {"files": [], "keys": []}
    for f in files:
        name = f.name.lower()
        if name in {"config.py", "settings.py", ".env", ".env.example", ".flaskenv"} or name.endswith(".toml"):
            rel = str(f.relative_to(root))
            out["files"].append(rel)
            src = read_text(f)
            for m in re.finditer(r"^\s*([A-Z_][A-Z0-9_]{2,})\s*[:=]", src, re.MULTILINE):
                out["keys"].append((rel, m.group(1)))
    return out


def analyse_requirements(files: list[Path], root: Path) -> list[tuple[str, list[str]]]:
    out = []
    for f in files:
        if f.name.lower() in {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "pipfile"}:
            rel = str(f.relative_to(root))
            src = read_text(f)
            lines = [l.strip() for l in src.splitlines() if l.strip() and not l.strip().startswith("#")]
            out.append((rel, lines[:60]))
    return out


def analyse_static(files: list[Path], root: Path) -> dict:
    css = [f for f in files if f.suffix.lower() in {".css", ".scss"}]
    js = [f for f in files if f.suffix.lower() in {".js", ".ts"}]
    imgs = [f for f in files if f.suffix.lower() in {".png", ".jpg", ".jpeg", ".svg", ".ico", ".webp"}]
    style_notes = []
    for f in css:
        src = read_text(f)
        has_vars = "--" in src and ":root" in src
        style_notes.append((str(f.relative_to(root)), f"lines={src.count(chr(10))+1}, uses_css_vars={has_vars}"))
    return {
        "css": [str(f.relative_to(root)) for f in css],
        "js": [str(f.relative_to(root)) for f in js],
        "images": len(imgs),
        "style_notes": style_notes,
    }


def analyse_tests(files: list[Path], root: Path) -> dict:
    out = {"test_files": [], "frameworks": set(), "count": 0}
    for f in files:
        rel = str(f.relative_to(root))
        if "/tests/" in rel or rel.startswith("tests/") or f.name.startswith("test_") or f.name.endswith("_test.py"):
            out["test_files"].append(rel)
    for f in files:
        src = read_text(f)
        if "import pytest" in src or "from pytest" in src:
            out["frameworks"].add("pytest")
        if "unittest" in src:
            out["frameworks"].add("unittest")
        out["count"] += len(re.findall(r"^\s*def\s+test_\w+", src, re.MULTILINE))
    out["frameworks"] = sorted(out["frameworks"])
    return out


def detect_auth_pattern(py_mods: list[PyModuleInfo]) -> dict:
    found = {
        "flask_login": False,
        "flask_wtf": False,
        "werkzeug_security": False,
        "custom_decorators": [],
        "role_checks": [],
        "password_hashing": [],
    }
    for m in py_mods:
        src = read_text(m.path)
        if "flask_login" in src or "LoginManager" in src:
            found["flask_login"] = True
        if "flask_wtf" in src or "FlaskForm" in src:
            found["flask_wtf"] = True
        if "werkzeug.security" in src or "generate_password_hash" in src:
            found["werkzeug_security"] = True
        for d in m.decorators:
            if d.endswith("login_required") or d.endswith("role_required") or "role_required" in d:
                found["custom_decorators"].append((m.rel, d))
        for m2 in re.finditer(r"def\s+(\w*role\w*)\s*\(", src):
            found["role_checks"].append((m.rel, m2.group(1)))
        for m2 in re.finditer(r"(generate_password_hash|check_password_hash)\s*\(", src):
            found["password_hashing"].append((m.rel, m2.group(1)))
    return found


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def build_report(root: Path) -> str:
    files, by_ext = walk_tree(root)
    py_mods = summarise_python(files, root)

    parts: list[str] = []
    parts.append(header("GULU RIF-MIS — PROJECT RECONNAISSANCE"))
    parts.append(f"Root: {root.resolve()}")
    parts.append(f"Files scanned (excluding ignored): {len(files)}")

    # File inventory
    parts.append(header("1. FILE INVENTORY BY EXTENSION"))
    for ext, count in sorted(by_ext.items(), key=lambda kv: -kv[1]):
        parts.append(f"  {ext:>8} : {count}")

    # Tree
    parts.append(header("2. DIRECTORY TREE (max depth 4)"))
    parts.append(render_tree(root, max_depth=4))

    # Python modules
    parts.append(header("3. PYTHON MODULES"))
    parts.append(f"Total Python files: {len(py_mods)}")
    parts.append(f"{'module':<45} {'lines':>6}  classes / functions (top)")
    parts.append("-" * 78)
    for m in sorted(py_mods, key=lambda x: x.rel):
        cls = ", ".join(m.classes[:4]) + ("…" if len(m.classes) > 4 else "")
        fn = ", ".join(m.functions[:6]) + ("…" if len(m.functions) > 6 else "")
        parts.append(f"{m.rel:<45} {m.lineno:>6}  {cls} | {fn}")
        if m.error:
            parts.append(f"   ⚠ {m.error}")

    # Flask patterns
    parts.append(header("4. FLASK PATTERNS"))
    fp = detect_flask_patterns(py_mods)
    parts.append(f"App factory present: {fp['has_app_factory']}")
    if fp["app_factory_line"]:
        parts.append(f"  → {fp['app_factory_line']}")
    parts.append(sub("Blueprints registered / declared"))
    for name, module, prefix in sorted(fp["blueprints"], key=lambda x: x[0]):
        parts.append(f"  • {name:<20} in {module:<40} url_prefix={prefix or '(none)'}")
    if not fp["blueprints"]:
        parts.append("  (none found — check for application-package structure)")
    parts.append(sub("Extensions instantiated"))
    for ext_name, locs in fp["extensions"].items():
        parts.append(f"  • {ext_name}: {', '.join(locs)}")
    parts.append(sub("Route table"))
    if fp["route_decorators"]:
        for module, path, methods in fp["route_decorators"]:
            parts.append(f"  {methods:<12} {path:<40} ({module})")
    else:
        parts.append("  (no @x.route decorators found)")
    parts.append(sub("before_request hooks"))
    for module, bp in fp["before_request"]:
        parts.append(f"  • {bp}.before_request  ({module})")
    parts.append(sub("errorhandler hooks"))
    for module, code in fp["error_handlers"]:
        parts.append(f"  • HTTP {code}  ({module})")

    # Models
    parts.append(header("5. DATABASE MODELS (SQLAlchemy)"))
    models = analyse_models(py_mods)
    if not models:
        parts.append("  (no SQLAlchemy models detected)")
    for module, classes in models:
        parts.append(sub(module))
        for cname, summary in classes:
            parts.append(f"  • {cname}")
            parts.append(f"      {summary}")

    # Templates
    parts.append(header("6. TEMPLATES"))
    tpl = analyse_templates(files, root)
    parts.append(f"Total templates: {tpl['count']}")
    parts.append(sub("By directory"))
    for d, n in sorted(tpl["by_dir"].items()):
        parts.append(f"  {d:<40} {n}")
    parts.append(sub("Template inheritance (extends)"))
    for rel, parent in tpl["extends"]:
        parts.append(f"  {rel:<45} → {parent}")
    parts.append(sub("Blocks defined"))
    for rel, blocks in tpl["blocks"].items():
        parts.append(f"  {rel:<45} {{{{' {' }}, '.join(blocks)}}}")
    parts.append(sub("Includes"))
    for rel, inc in tpl["includes"]:
        parts.append(f"  {rel:<45} → {inc}")
    parts.append(sub("Signal usage"))
    parts.append(f"  url_for() used in {tpl['uses_url_for']} templates")
    parts.append(f"  flash messages in {tpl['uses_flash']} templates")
    parts.append(f"  CSRF-protected forms: {len(tpl['forms_or_csrf'])} templates")
    parts.append(sub("Bootstrap classes (top 15)"))
    for cls, n in tpl["bootstrap"].most_common(15):
        parts.append(f"  {cls:<20} {n}")

    # Static
    parts.append(header("7. STATIC ASSETS & STYLING"))
    st = analyse_static(files, root)
    parts.append(f"CSS files: {st['css']}")
    parts.append(f"JS files : {st['js']}")
    parts.append(f"Images   : {st['images']}")
    if st["style_notes"]:
        parts.append(sub("CSS notes"))
        for name, note in st["style_notes"]:
            parts.append(f"  {name}: {note}")

    # Config
    parts.append(header("8. CONFIGURATION"))
    cfg = analyse_config(files, root)
    parts.append(f"Config/env files: {cfg['files'] or '(none)'}")
    keys = defaultdict(list)
    for f, k in cfg["keys"]:
        keys[k].append(f)
    if keys:
        parts.append(sub("Config keys"))
        for k, locs in sorted(keys.items()):
            parts.append(f"  {k:<30} {', '.join(sorted(set(locs)))}")

    # Requirements
    parts.append(header("9. DEPENDENCIES"))
    reqs = analyse_requirements(files, root)
    if not reqs:
        parts.append("  (no requirements/pyproject found)")
    for rel, lines in reqs:
        parts.append(sub(rel))
        for line in lines:
            parts.append(f"  {line}")

    # Auth
    parts.append(header("10. AUTH / RBAC PATTERN"))
    a = detect_auth_pattern(py_mods)
    parts.append(f"Flask-Login present       : {a['flask_login']}")
    parts.append(f"Flask-WTF present         : {a['flask_wtf']}")
    parts.append(f"werkzeug.security hashing : {a['werkzeug_security']}")
    parts.append(sub("Custom decorators"))
    for module, dec in a["custom_decorators"]:
        parts.append(f"  • {dec}  ({module})")
    parts.append(sub("Role-related functions"))
    for module, fn in a["role_checks"]:
        parts.append(f"  • {fn}()  ({module})")
    parts.append(sub("Password hashing call sites"))
    for module, fn in a["password_hashing"]:
        parts.append(f"  • {fn}()  ({module})")

    # Tests
    parts.append(header("11. TESTS"))
    t = analyse_tests(files, root)
    parts.append(f"Frameworks detected: {t['frameworks'] or '(none)'}")
    parts.append(f"Test functions     : {t['count']}")
    parts.append(f"Test files         : {len(t['test_files'])}")
    for f in t["test_files"]:
        parts.append(f"  {f}")

    # Style signals
    parts.append(header("12. STYLE SIGNALS"))
    typed = sum(1 for m in py_mods if m.has_type_hints)
    doc = sum(1 for m in py_mods if m.docstring)
    parts.append(f"Modules with type hints : {typed} / {len(py_mods)}")
    parts.append(f"Modules with docstring  : {doc} / {len(py_mods)}")
    naming = Counter()
    for m in py_mods:
        for cls in m.classes:
            naming["PascalCase class" if cls[:1].isupper() else "non-Pascal class"] += 1
        for fn in m.functions:
            if fn.startswith("_"):
                naming["_private function"] += 1
            elif fn.islower():
                naming["snake_case function"] += 1
            else:
                naming["other function"] += 1
    for k, v in naming.most_common():
        parts.append(f"  {k:<25} {v}")

    # Gap checklist vs spec
    parts.append(header("13. GAP CHECKLIST vs RIF-MIS SPEC (M02 + M04 slices)"))
    checks = [
        ("Application factory (create_app)", fp["has_app_factory"]),
        ("Blueprints for auth / main / public", bool(fp["blueprints"])),
        ("User model / role field", any("user" in m.rel.lower() or "auth" in m.rel.lower() for m in py_mods) or bool(models)),
        ("Login route(s)", any(p == "/login" or p.endswith("/login") for _, p, _ in fp["route_decorators"])),
        ("Logout route(s)", any("logout" in p for _, p, _ in fp["route_decorators"])),
        ("Role decorator / guard", bool(a["custom_decorators"])),
        ("Password hashing call site", bool(a["password_hashing"])),
        ("Base template + navbar", any(parent for _, parent in tpl["extends"])),
        ("Bootstrap styling", bool(tpl["bootstrap"])),
        ("Config module / env keys", bool(cfg["files"])),
        ("Requirements pinned", bool(reqs)),
        ("Audit / login-event logging", any("audit" in m.rel.lower() or "AuditLog" in "".join(m.classes) for m in py_mods)),
    ]
    for label, ok in checks:
        mark = "✔" if ok else "✘"
        parts.append(f"  [{mark}] {label}")

    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Reconnaissance for Gulu RIF-MIS codebase.")
    ap.add_argument("root", nargs="?", default=".", help="Project root (default: cwd)")
    ap.add_argument("--out", help="Write report to this file instead of stdout")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    report = build_report(root)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Wrote {args.out} ({len(report)} bytes)")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())