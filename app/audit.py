from flask import has_request_context, request

from app.extensions import db
from app.models import AuditEvent


def record_audit(action: str, user_id: int | None = None, details: str | None = None) -> None:
    ip = None
    if has_request_context():
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()
    event = AuditEvent(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip,
    )
    db.session.add(event)
    db.session.commit()
