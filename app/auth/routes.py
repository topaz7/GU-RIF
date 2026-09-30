from urllib.parse import urlsplit

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user

from app.audit import record_audit
from app.auth.forms import LoginForm, RegisterForm
from app.extensions import db
from app.models import ROLE_APPLICANT, ROLE_DRGT_ADMIN, User, utcnow

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _is_safe_next_url(target: str | None) -> bool:
    """Allow only same-site relative paths (blocks //host, /\\host, scheme:...)."""
    if not target:
        return False
    target = target.strip()
    if not target.startswith("/") or target.startswith("//") or "\\" in target:
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc


def _workspace_for(user: User) -> str:
    if user.has_role(ROLE_DRGT_ADMIN):
        return url_for("dashboard.drgt")
    return url_for("dashboard.applicant")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(_workspace_for(current_user))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if User.query.filter_by(email=email).first():
            form.email.errors.append("An account with this email already exists.")
            return render_template("auth/register.html", form=form)

        user = User(
            email=email,
            full_name=form.full_name.data.strip(),
            role=ROLE_APPLICANT,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        record_audit(
            "user.registered",
            user_id=user.id,
            details=f"Self-registered as {ROLE_APPLICANT}",
        )
        record_audit(
            "role.assigned",
            user_id=user.id,
            details=f"Assigned role {ROLE_APPLICANT}",
        )
        session.permanent = True
        login_user(user, remember=False)
        flash("Account created. You are signed in as an applicant.", "success")
        return redirect(url_for("dashboard.applicant"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(_workspace_for(current_user))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is None or not user.check_password(form.password.data):
            record_audit(
                "auth.login_failed",
                user_id=user.id if user else None,
                details=f"Failed sign-in for {email}",
            )
            flash("Invalid email or password.", "danger")
            return render_template("auth/login.html", form=form)

        if not user.is_active:
            record_audit(
                "auth.login_blocked",
                user_id=user.id,
                details="Inactive account",
            )
            flash("This account is inactive. Contact DRGT.", "danger")
            return render_template("auth/login.html", form=form)

        user.last_login_at = utcnow()
        db.session.commit()
        session.permanent = True  # apply PERMANENT_SESSION_LIFETIME timeout
        login_user(user, remember=False)
        record_audit("auth.login", user_id=user.id, details=f"Signed in as {user.role}")
        next_url = request.args.get("next")
        if _is_safe_next_url(next_url):
            return redirect(next_url)
        return redirect(_workspace_for(user))

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if current_user.is_authenticated:
        record_audit("auth.logout", user_id=current_user.id)
        logout_user()
        flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))
