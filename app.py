from flask import Flask, jsonify, render_template, request, send_file

from database.database import Database
from reports.report_generator import ReportGenerator
from reports.html_exporter import HTMLReportExporter
from scanner.controller import ScanController
from scanner.target_validator import TargetValidator


def create_app():
    """Create and configure the nvscan Flask application."""

    app = Flask(__name__)

    controller = ScanController()
    database = Database()
    validator = TargetValidator()
    report_generator = ReportGenerator()
    html_exporter = HTMLReportExporter()

    database.initialize()

    def detect_target_type(target):
        """Determine the basic type of a validated target."""

        if "/" in target:
            if ":" in target:
                return "ipv6_network"

            return "ipv4_network"

        if ":" in target:
            return "ipv6"

        parts = target.split(".")

        if len(parts) == 4 and all(
            part.isdigit()
            for part in parts
        ):
            return "ipv4"

        return "hostname"

    @app.get("/")
    def index():
        """Display the main dashboard."""

        return render_template(
            "dashboard.html"
        )

    @app.get("/dashboard")
    def dashboard():
        """Display the main dashboard."""

        return render_template(
            "dashboard.html"
        )

    @app.get("/targets")
    def targets_page():
        """Display the targets page."""

        return render_template(
            "targets.html"
        )

    @app.get("/scans")
    def scans_page():
        """Display the scan history page."""

        return render_template(
            "scan_history.html"
        )

    @app.get("/reports")
    def reports_page():
        """Display the reports page."""

        return render_template(
            "report.html"
        )

    @app.get("/api/health")
    def health():
        """Return API health status."""

        return jsonify(
            {
                "status": "healthy",
                "service": "nvscan-api",
            }
        )

    @app.get("/api/dashboard")
    def dashboard_api():
        """Return dashboard summary information."""

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

            high_risk_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM risk_scores
                WHERE priority IN (
                    'HIGH',
                    'CRITICAL'
                )
                """
            ).fetchone()[0]

            recent_scans = connection.execute(
                """
                SELECT
                    scans.id,
                    scans.status,
                    scans.started_at,
                    scans.completed_at,
                    targets.target,
                    targets.target_type
                FROM scans
                JOIN targets
                    ON scans.target_id = targets.id
                ORDER BY scans.id DESC
                LIMIT 10
                """
            ).fetchall()

        return jsonify(
            {
                "success": True,
                "summary": {
                    "targets": target_count,
                    "scans": scan_count,
                    "findings": finding_count,
                    "high_risk": high_risk_count,
                },
                "recent_scans": [
                    dict(scan)
                    for scan in recent_scans
                ],
            }
        )

    @app.get("/api/targets")
    def get_targets():
        """Return all registered targets."""

        targets = database.get_all_targets()

        return jsonify(
            {
                "success": True,
                "count": len(targets),
                "targets": targets,
            }
        )

    @app.post("/api/targets")
    def create_target():
        """Register a new target."""

        data = request.get_json(
            silent=True
        )

        if not isinstance(data, dict):
            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Request body must be "
                        "a JSON object."
                    ),
                }
            ), 400

        target = data.get("target")

        if not isinstance(target, str):
            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Target is required and "
                        "must be a string."
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
                    "error": error,
                }
            ), 400

        target_type = detect_target_type(
            normalized_target
        )

        existing = database.get_target_by_value(
            normalized_target
        )

        if existing is not None:
            return jsonify(
                {
                    "success": True,
                    "created": False,
                    "message": (
                        "Target is already registered."
                    ),
                    "target": existing,
                }
            ), 200

        target_id = database.add_target(
            normalized_target,
            target_type,
        )

        created_target = database.get_target(
            target_id
        )

        return jsonify(
            {
                "success": True,
                "created": True,
                "message": (
                    "Target registered successfully."
                ),
                "target": created_target,
            }
        ), 201

    @app.get("/api/targets/<int:target_id>")
    def get_target(target_id):
        """Return target details and scan history."""

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
                "target": result["target"],
                "scans": result["scans"],
            }
        )

    @app.get("/api/scans")
    def get_scans():
        """Return scan history."""

        with database.connect() as connection:

            scans = connection.execute(
                """
                SELECT
                    scans.id,
                    scans.target_id,
                    scans.status,
                    scans.started_at,
                    scans.completed_at,
                    targets.target,
                    targets.target_type,
                    COUNT(DISTINCT findings.id)
                        AS finding_count
                FROM scans
                JOIN targets
                    ON scans.target_id = targets.id
                LEFT JOIN findings
                    ON findings.scan_id = scans.id
                GROUP BY
                    scans.id,
                    scans.target_id,
                    scans.status,
                    scans.started_at,
                    scans.completed_at,
                    targets.target,
                    targets.target_type
                ORDER BY scans.id DESC
                """
            ).fetchall()

        return jsonify(
            {
                "success": True,
                "count": len(scans),
                "scans": [
                    dict(scan)
                    for scan in scans
                ],
            }
        )

    @app.post("/api/scans")
    def create_scan():
        """Run a vulnerability scan."""

        data = request.get_json(
            silent=True
        )

        if not isinstance(data, dict):
            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Request body must be "
                        "a JSON object."
                    ),
                }
            ), 400

        target = data.get("target")

        if not isinstance(target, str):
            return jsonify(
                {
                    "success": False,
                    "error": (
                        "Target is required and "
                        "must be a string."
                    ),
                }
            ), 400

        result = controller.scan(target)

        if not result["success"]:
            return jsonify(
                {
                    "success": False,
                    "error": result["error"],
                }
            ), 400

        return jsonify(
            {
                "success": True,
                "scan_id": result["scan_id"],
                "target": result["target"],
                "summary": result["summary"],
                "findings": result["findings"],
            }
        )

    @app.get("/api/scans/<int:scan_id>")
    def get_scan(scan_id):
        """Return stored results for a scan."""

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

        findings = []

        for finding in result["findings"]:

            finding = dict(finding)

            evidence = finding.get(
                "evidence"
            )

            if evidence:
                try:
                    import json

                    finding["evidence"] = json.loads(
                        evidence
                    )

                except (
                    json.JSONDecodeError,
                    TypeError,
                ):
                    pass

            findings.append(finding)

        return jsonify(
            {
                "success": True,
                "scan": result["scan"],
                "hosts": result["hosts"],
                "services": result["services"],
                "findings": findings,
            }
        )
    @app.get("/scans/<int:scan_id>")
    def scan_results_page(scan_id):
        """Display stored results for a scan."""

        result = database.get_scan_results(scan_id)

        if result is None:
            return (
                render_template(
                    "results.html",
                    scan=None,
                    hosts=[],
                    services=[],
                    findings=[],
                ),
                404,
            )

        findings = []

        for finding in result["findings"]:

            finding = dict(finding)

            evidence = finding.get(
                "evidence"
            )

            if evidence:
                try:
                    import json

                    finding["evidence"] = json.loads(
                        evidence
                    )

                except (
                    json.JSONDecodeError,
                    TypeError,
                ):
                    pass

            findings.append(finding)

        return render_template(
            "results.html",
            scan=result["scan"],
            hosts=result["hosts"],
            services=result["services"],
            findings=findings,
        )
    @app.get("/api/reports/<int:scan_id>/html")
    def download_html_report(scan_id):
        """Generate and download an HTML security report."""

        scan_result = database.get_scan_results(scan_id)

        if scan_result is None:
            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        findings = []

        for finding in scan_result["findings"]:
            finding = dict(finding)

            evidence = finding.get("evidence")

            if evidence:
                try:
                    import json

                    finding["evidence"] = json.loads(
                        evidence
                    )
                except (
                    json.JSONDecodeError,
                    TypeError,
                ):
                    pass

            findings.append(finding)

        scan_result["findings"] = findings

        report = report_generator.generate(
            scan_result
        )

        html = html_exporter.generate(report)

        from io import BytesIO

        return send_file(
            BytesIO(
                html.encode("utf-8")
            ),
            mimetype="text/html",
            as_attachment=True,
            download_name=(
                f"nvscan_scan_{scan_id}_report.html"
            ),
        )

    @app.get("/api/reports/<int:scan_id>")
    def get_report(scan_id):
        """Generate a structured report for a stored scan."""

        scan_result = database.get_scan_results(scan_id)

        if scan_result is None:
            return jsonify(
                {
                    "success": False,
                    "error": "Scan not found.",
                }
            ), 404

        findings = []

        for finding in scan_result["findings"]:
            finding = dict(finding)

            evidence = finding.get("evidence")

            if evidence:
                try:
                    import json

                    finding["evidence"] = json.loads(
                        evidence
                    )
                except (
                    json.JSONDecodeError,
                    TypeError,
                ):
                    pass

            findings.append(finding)

        scan_result["findings"] = findings

        report = report_generator.generate(
            scan_result
        )

        return jsonify(
            {
                "success": True,
                **report,
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
