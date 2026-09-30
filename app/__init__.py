import os

import click

from flask import Flask, redirect, render_template, url_for
from flask_login import current_user

from app.audit import record_audit
from app.extensions import csrf, db, login_manager, migrate
from app.models import ROLE_DRGT_ADMIN, User
from config import Config


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.auth.routes import auth_bp
    from app.dashboard.routes import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/workspace")
    def workspace_root():
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        if current_user.has_role(ROLE_DRGT_ADMIN):
            return redirect(url_for("dashboard.drgt"))
        return redirect(url_for("dashboard.applicant"))

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.cli.command("seed-admin")
    def seed_admin_command():
        """Create the DRGT administrator account if it does not exist."""
        _ensure_drgt_admin(app)
        click.echo("DRGT administrator account is present.")

    return app


def _ensure_drgt_admin(app: Flask) -> None:
    email = app.config["SEED_ADMIN_EMAIL"].strip().lower()
    if User.query.filter_by(email=email).first():
        return
    admin = User(
        email=email,
        full_name="DRGT Administrator",
        role=ROLE_DRGT_ADMIN,
    )
    admin.set_password(app.config["SEED_ADMIN_PASSWORD"])
    db.session.add(admin)
    db.session.flush()
    record_audit(
        "user.seeded",
        user_id=admin.id,
        details=f"Seeded DRGT administrator {email}",
    )
    record_audit(
        "role.assigned",
        user_id=admin.id,
        details=f"Assigned role {ROLE_DRGT_ADMIN}",
    )
    app.logger.info("Seeded DRGT administrator account: %s", email)
