from flask import Blueprint, render_template

from app.auth.decorators import role_required
from app.models import ROLE_APPLICANT, ROLE_DRGT_ADMIN

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/workspace")


@dashboard_bp.route("/applicant")
@role_required(ROLE_APPLICANT)
def applicant():
    return render_template("dashboard/applicant.html")


@dashboard_bp.route("/drgt")
@role_required(ROLE_DRGT_ADMIN)
def drgt():
    return render_template("dashboard/drgt.html")
