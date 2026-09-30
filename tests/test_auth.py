import pytest

from app import _ensure_drgt_admin, create_app
from app.extensions import db
from app.models import ROLE_APPLICANT, AuditEvent, User


@pytest.fixture()
def app():
    app = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SEED_ADMIN_EMAIL": "drgt.admin@gu.ac.ug",
            "SEED_ADMIN_PASSWORD": "ChangeMe123!",
            "SECRET_KEY": "test-secret",
        }
    )
    with app.app_context():
        db.create_all()
        _ensure_drgt_admin(app)
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def test_seeded_drgt_admin_can_sign_in(client, app):
    response = client.post(
        "/auth/login",
        data={"email": "drgt.admin@gu.ac.ug", "password": "ChangeMe123!"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/workspace/drgt" in response.headers["Location"]
    with app.app_context():
        events = [event.action for event in AuditEvent.query.all()]
        assert "auth.login" in events
        assert "role.assigned" in events


def test_register_creates_applicant_and_blocks_drgt_workspace(client, app):
    response = client.post(
        "/auth/register",
        data={
            "full_name": "Test Applicant",
            "email": "pi@gu.ac.ug",
            "password": "Password1",
            "confirm_password": "Password1",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/workspace/applicant" in response.headers["Location"]

    forbidden = client.get("/workspace/drgt")
    assert forbidden.status_code == 403

    allowed = client.get("/workspace/applicant")
    assert allowed.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email="pi@gu.ac.ug").one()
        assert user.role == ROLE_APPLICANT
        actions = [event.action for event in AuditEvent.query.filter_by(user_id=user.id)]
        assert "user.registered" in actions
        assert "role.assigned" in actions


def test_drgt_cannot_open_applicant_workspace(client):
    client.post(
        "/auth/login",
        data={"email": "drgt.admin@gu.ac.ug", "password": "ChangeMe123!"},
    )
    response = client.get("/workspace/applicant")
    assert response.status_code == 403


def test_login_required_for_workspaces(client):
    assert client.get("/workspace/applicant").status_code == 302
    assert client.get("/workspace/drgt").status_code == 302


ADMIN_LOGIN = {"email": "drgt.admin@gu.ac.ug", "password": "ChangeMe123!"}


@pytest.mark.parametrize(
    "next_url",
    [
        "//evil.example.com",
        r"/\evil.example.com",
        "https://evil.example.com/",
        "javascript:alert(1)",
        " //evil.example.com",
    ],
)
def test_login_rejects_offsite_next_url(client, next_url):
    response = client.post("/auth/login", query_string={"next": next_url}, data=ADMIN_LOGIN)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/workspace/drgt")


def test_login_follows_local_next_url(client):
    response = client.post(
        "/auth/login", query_string={"next": "/workspace/drgt?tab=calls"}, data=ADMIN_LOGIN
    )
    assert response.headers["Location"] == "/workspace/drgt?tab=calls"


def test_login_sets_expiring_session_cookie(client, app):
    response = client.post("/auth/login", data=ADMIN_LOGIN)
    cookie = next(
        c for c in response.headers.getlist("Set-Cookie")
        if c.startswith(app.config["SESSION_COOKIE_NAME"] + "=")
    )
    assert "Expires=" in cookie
