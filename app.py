from io import BytesIO
import os

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from auth import (
    authenticate_user,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from database.database import Database

from reports.report_generator import ReportGenerator
from reports.html_exporter import HTMLReportExporter
from reports.pdf_exporter import PDFReportExporter

from scanner.controller import ScanController
from scanner.comparison_engine import ComparisonEngine
from scanner.target_validator import TargetValidator


def create_app():
    """Create and configure the nvscan Flask application."""

    app = Flask(__name__)

    app.secret_key = os.environ.get(
        "NVSCAN_SECRET_KEY",
        "nvscan-development-secret-change-me",
    )

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    controller = ScanController()
    database = Database()
    validator = TargetValidator()

    report_generator = ReportGenerator()
    html_exporter = HTMLReportExporter()
    pdf_exporter = PDFReportExporter()

    comparison_engine = ComparisonEngine(
        database
    )

    database.initialize()

    def detect_target_type(target):
        """Determine the basic type of a validated target."""

        if "/" in target:

            if ":" in target:
                return "ipv6_network"

            return "ipv4_network"

        if ":" in target:
            return "ipv6"

        return "ipv4"

    @app.context_processor
    def inject_current_user():
        """Make the current user available to templates."""

        return {
            "current_user": current_user(
                database
            )
        }

    # ================================================================
    # AUTHENTICATION
    # ================================================================

    @app.get("/login")
    def login():
        """Display the login page."""

        if current_user(database) is not None:
            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error=None,
        )

    @app.post("/login")
    def login_post():
        """Authenticate a user."""

        username = (
            request.form.get(
                "username",
                "",
            )
            .strip()
        )

        password = request.form.get(
            "password",
            "",
        )

        if not username or not password:

            return render_template(
                "login.html",
                error=(
                    "Username and password "
                    "are required."
                ),
            ), 400

        user = authenticate_user(
            database,
            username,
            password,
        )

        if user is None:

            return render_template(
                "login.html",
                error=(
                    "Invalid username or "
                    "password."
                ),
            ), 401

        login_user(user)

        return redirect(
            url_for("dashboard")
        )

    @app.post("/logout")
    def logout():
        """Log out the current user."""

        logout_user()

        return redirect(
            url_for("login")
        )

    # ================================================================
    # PUBLIC HEALTH ENDPOINT
    # ================================================================

    @app.get("/api/health")
    def health():
        """Return application health information."""

        return jsonify(
            {
                "success": True,
                "application": "nvscan",
                "status": "healthy",
            }
        )

    # ================================================================
    # PROTECTED WEB PAGES
    # ================================================================

    @app.get("/")
    @login_required
    def index():
        """Redirect the root page to the dashboard."""

        return redirect(
            url_for("dashboard")
        )

    @app.get("/dashboard")
    @login_required
    def dashboard():
        """Render the main dashboard."""

        return render_template(
            "dashboard.html"
        )

    @app.get("/targets")
    @login_required
    def targets_page():
        """Render the target management page."""

        return render_template(
            "targets.html"
        )

    @app.get("/scans")
    @login_required
    def scans_page():
        """Render the scan history page."""

        return render_template(
            "scan_history.html"
        )

    @app.get("/reports")
    @login_required
    def reports_page():
        """Render the reports page."""

        return render_template(
            "report.html"
        )

    @app.get(
        "/comparison/<int:scan_id>"
    )
    @login_required
    def comparison_page(scan_id):
        """Render scan comparison page."""

        result = comparison_engine.compare(
            scan_id
        )

        if result is None:

            return (
                "Scan comparison not available.",
                404,
            )

        return render_template(
            "comparison.html",
            comparison=result,
        )

    @app.get(
        "/scans/<int:scan_id>"
    )
    @login_required
    def scan_results_page(scan_id):
        """Render detailed scan results."""

        result = database.get_scan_results(
            scan_id
        )

        if result is None:

            return (
                "Scan not found.",
                404,
            )

        return render_template(
            "scan_results.html",
            scan=result["scan"],
            hosts=result["hosts"],
            services=result["services"],
            findings=result["findings"],
        )

    # ================================================================
    # DASHBOARD API
    # ================================================================

    @app.get("/api/dashboard")
    @login_required
    def dashboard_data():
        """Return dashboard statistics."""

        with database.connect() as connection:

            target_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM targets
                """
            ).fetchone()[0]

            scan_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM scans
                """
            ).fetchone()[0]

            finding_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM findings
                """
            ).fetchone()[0]

            completed_scans = connection.execute(
                """
                SELECT COUNT(*)
                FROM scans
                WHERE status = 'completed'
                """
            ).fetchone()[0]

        return jsonify(
            {
                "success": True,
                "targets": target_count,
                "scans": scan_count,
                "findings": finding_count,
                "completed_scans": completed_scans,
            }
        )

    # ================================================================
    # HISTORICAL COMPARISON API
    # ================================================================

    @app.get(
        "/api/scans/<int:scan_id>/comparison"
    )
    @login_required
    def scan_comparison_api(scan_id):
        """Return historical scan comparison data."""

        result = comparison_engine.compare(
            scan_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Scan comparison "
                        "not available."
                    ),
                }
            ), 404

        return jsonify(
            {
                "success": True,
                "comparison": result,
            }
        )

    # ================================================================
    # TARGET API
    # ================================================================

    @app.get("/api/targets")
    @login_required
    def get_targets():
        """Return all registered targets."""

        targets = database.get_all_targets()

        return jsonify(
            {
                "success": True,
                "targets": targets,
            }
        )

    @app.post("/api/targets")
    @login_required
    def create_target():
        """Validate and register a target."""

        data = request.get_json(
            silent=True
        ) or {}

        target = str(
            data.get(
                "target",
                "",
            )
        ).strip()

        if not target:

            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Target is required."
                    ),
                }
            ), 400

        valid, normalized_target, error = (
            validator.validate(target)
        )

        if not valid:

            return jsonify(
                {
                    "success": False,
                    "error": (
                        error
                        or "Invalid target."
                    ),
                }
            ), 400

        target_type = detect_target_type(
            normalized_target
        )

        target_id = database.add_target(
            normalized_target,
            target_type,
        )

        return jsonify(
            {
                "success": True,
                "target_id": target_id,
                "target": normalized_target,
                "target_type": target_type,
            }
        )

    @app.get(
        "/api/targets/<int:target_id>"
    )
    @login_required
    def get_target(target_id):
        """Return target details."""

        result = database.get_target_details(
            target_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Target not found.",
                }
            ), 404

        return jsonify(
            {
                "success": True,
                **result,
            }
        )

    # ================================================================
    # SCAN HISTORY API
    # ================================================================

    @app.get("/api/scans")
    @login_required
    def get_scans():
        """Return all recorded scans for scan history."""

        scans = database.get_all_scans()

        return jsonify(
            {
                "success": True,
                "scans": scans,
            }
        )

    # ================================================================
    # SCAN API
    # ================================================================

    @app.post("/api/scans")
    @login_required
    def create_scan():
        """Start a vulnerability scan."""

        data = request.get_json(
            silent=True
        ) or {}

        target = str(
            data.get(
                "target",
                "",
            )
        ).strip()

        if not target:

            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Target is required."
                    ),
                }
            ), 400

        valid, normalized_target, error = (
            validator.validate(target)
        )

        if not valid:

            return jsonify(
                {
                    "success": False,
                    "error": (
                        error
                        or "Invalid target."
                    ),
                }
            ), 400

        try:

            result = controller.scan(
                normalized_target
            )

            return jsonify(
                {
                    "success": True,
                    "result": result,
                }
            )

        except Exception as exc:

            app.logger.exception(
                "Scan failed."
            )

            return jsonify(
                {
                    "success": False,
                    "error": str(exc),
                }
            ), 500

    @app.get(
        "/api/scans/<int:scan_id>"
    )
    @login_required
    def get_scan(scan_id):
        """Return a complete stored scan."""

        result = database.get_scan_results(
            scan_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        return jsonify(
            {
                "success": True,
                "result": result,
            }
        )

    # ================================================================
    # REMEDIATION API
    # ================================================================

    @app.get(
        "/api/scans/<int:scan_id>/remediation"
    )
    @login_required
    def get_remediation(scan_id):
        """Return remediation guidance for a scan."""

        result = database.get_scan_results(
            scan_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        remediation_items = []

        for finding in result["findings"]:

            remediation = finding.get(
                "remediation"
            )

            remediation_items.append(
                {
                    "finding_id": finding.get(
                        "finding_id"
                    ),
                    "title": finding.get(
                        "title"
                    ),
                    "severity": finding.get(
                        "severity"
                    ),
                    "priority": finding.get(
                        "priority"
                    ),
                    "score": finding.get(
                        "score"
                    ),
                    "risk": {
                        "score": finding.get(
                            "score"
                        ),
                        "priority": finding.get(
                            "priority"
                        ),
                        "exposure": finding.get(
                            "exposure"
                        ),
                    },
                    "remediation": remediation,
                }
            )

        return jsonify(
            {
                "success": True,
                "scan_id": scan_id,
                "count": len(
                    remediation_items
                ),
                "remediation": remediation_items,
            }
        )

    # ================================================================
    # HTML REPORT
    # ================================================================

    @app.get(
        "/api/reports/<int:scan_id>/html"
    )
    @login_required
    def generate_html_report(scan_id):
        """Generate and return an HTML scan report."""

        result = database.get_scan_results(
            scan_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        report = report_generator.generate(
            result
        )

        html_content = html_exporter.export(
            report
        )

        return html_content

    # ================================================================
    # PDF REPORT
    # ================================================================

    @app.get(
        "/api/reports/<int:scan_id>/pdf"
    )
    @login_required
    def generate_pdf_report(scan_id):
        """Generate and return a PDF scan report."""

        result = database.get_scan_results(
            scan_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        try:

            report = report_generator.generate(
                result
            )

            pdf_content = pdf_exporter.generate(
                report
            )

            pdf_buffer = BytesIO(
                pdf_content
            )

            pdf_buffer.seek(0)

            return send_file(
                pdf_buffer,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=(
                    f"nvscan_scan_"
                    f"{scan_id}_report.pdf"
                ),
            )

        except Exception:

            app.logger.exception(
                "PDF report generation failed."
            )

            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Unable to generate "
                        "PDF report."
                    ),
                }
            ), 500

    # ================================================================
    # STRUCTURED REPORT API
    # ================================================================

    @app.get(
        "/api/reports/<int:scan_id>"
    )
    @login_required
    def generate_report(scan_id):
        """Return a structured security report."""

        result = database.get_scan_results(
            scan_id
        )

        if result is None:

            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        report = report_generator.generate(
            result
        )

        return jsonify(
            {
                "success": True,
                "report": report,
            }
        )

    return app


app = create_app()


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
