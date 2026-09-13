import os
import sys
import tempfile

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
        )
    ),
)

from app import app
from database.database import Database
from remediation_engine.engine import RemediationEngine
from risk_engine.scorer import RiskScorer
from scanner.finding_engine import FindingEngine
from scanner.target_validator import TargetValidator
from vulnerability_engine.correlator import CVECorrelator


# ============================================================
# TARGET VALIDATION TESTS
# ============================================================

def test_valid_ipv4_target():
    validator = TargetValidator()

    result = validator.validate(
        "192.168.1.10"
    )

    assert result[0] is True
    assert result[1] == "192.168.1.10"
    assert result[2] is None


def test_valid_hostname_target():
    validator = TargetValidator()

    result = validator.validate(
        "example.com"
    )

    assert result[0] is True
    assert result[1] == "example.com"
    assert result[2] is None


def test_invalid_target():
    validator = TargetValidator()

    result = validator.validate(
        "not a valid target !!!"
    )

    assert result[0] is False
    assert result[1] is None
    assert isinstance(result[2], str)


# ============================================================
# RISK ENGINE TESTS
# ============================================================

def test_risk_score_medium():
    scorer = RiskScorer()

    finding = {
        "finding_id": "TEST-001",
        "title": "Test medium vulnerability",
        "severity": "MEDIUM",
        "confidence": "HIGH",
    }

    result = scorer.score_finding(
        finding,
        exposure="NETWORK",
    )

    assert isinstance(result, dict)
    assert "risk" in result

    risk = result["risk"]

    assert risk["score"] == 50.0
    assert risk["priority"] == "MEDIUM"
    assert risk["severity"] == "MEDIUM"
    assert risk["confidence"] == "HIGH"


def test_risk_score_critical():
    scorer = RiskScorer()

    finding = {
        "finding_id": "TEST-002",
        "title": "Test critical vulnerability",
        "severity": "CRITICAL",
        "confidence": "HIGH",
    }

    result = scorer.score_finding(
        finding,
        exposure="NETWORK",
    )

    assert isinstance(result, dict)
    assert "risk" in result

    risk = result["risk"]

    assert risk["score"] == 100.0
    assert risk["priority"] == "CRITICAL"
    assert risk["severity"] == "CRITICAL"


# ============================================================
# FINDING ENGINE TESTS
# ============================================================

def test_finding_engine_detects_ftp():
    engine = FindingEngine()

    normalized_result = {
        "source": "nmap",
        "type": "service",
        "host": "192.168.1.10",
        "hostname": None,
        "port": 21,
        "protocol": "tcp",
        "state": "open",
        "service": "ftp",
        "product": "vsftpd",
        "version": "3.0.3",
        "evidence": None,
    }

    findings = engine.analyze(
        [normalized_result]
    )

    assert isinstance(findings, list)

    finding_ids = [
        finding.get("finding_id")
        for finding in findings
    ]

    assert "NET-002" in finding_ids


def test_finding_engine_detects_telnet():
    engine = FindingEngine()

    normalized_result = {
        "source": "nmap",
        "type": "service",
        "host": "192.168.1.10",
        "hostname": None,
        "port": 23,
        "protocol": "tcp",
        "state": "open",
        "service": "telnet",
        "product": "telnetd",
        "version": "1.0",
        "evidence": None,
    }

    findings = engine.analyze(
        [normalized_result]
    )

    assert isinstance(findings, list)

    finding_ids = [
        finding.get("finding_id")
        for finding in findings
    ]

    assert "NET-003" in finding_ids


# ============================================================
# REMEDIATION ENGINE TESTS
# ============================================================

def test_ftp_remediation():
    engine = RemediationEngine()

    finding = {
        "finding_id": "NET-002",
        "title": "FTP service exposed",
        "severity": "MEDIUM",
        "priority": "MEDIUM",
    }

    result = engine.generate(
        finding
    )

    assert isinstance(result, dict)
    assert result["finding_id"] == "NET-002"
    assert result["action"]
    assert isinstance(result["steps"], list)
    assert len(result["steps"]) > 0
    assert isinstance(result["verification"], list)
    assert len(result["verification"]) > 0


def test_hsts_remediation():
    engine = RemediationEngine()

    finding = {
        "finding_id": "WEB-009",
        "title": "Missing HSTS security header",
        "severity": "MEDIUM",
        "priority": "MEDIUM",
    }

    result = engine.generate(
        finding
    )

    assert isinstance(result, dict)
    assert result["finding_id"] == "WEB-009"
    assert result["action"]
    assert len(result["steps"]) > 0
    assert len(result["verification"]) > 0


# ============================================================
# CVE CORRELATION TESTS
# ============================================================

def test_apache_cve_correlation():
    correlator = CVECorrelator()

    result = {
        "host": "192.168.1.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.49",
        "state": "open",
    }

    matches = correlator.correlate(
        result
    )

    assert isinstance(matches, list)

    cve_ids = [
        match.get("finding_id")
        for match in matches
    ]

    assert "CVE-2021-41773" in cve_ids


def test_current_apache_version_does_not_match_old_cve():
    correlator = CVECorrelator()

    result = {
        "host": "192.168.1.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.63",
        "state": "open",
    }

    matches = correlator.correlate(
        result
    )

    assert isinstance(matches, list)

    cve_ids = [
        match.get("finding_id")
        for match in matches
    ]

    assert "CVE-2021-41773" not in cve_ids


# ============================================================
# DATABASE TEST HELPERS
# ============================================================

def create_test_database():
    temporary_file = tempfile.NamedTemporaryFile(
        suffix=".db",
        delete=False,
    )

    temporary_file.close()

    database = Database(
        database_path=temporary_file.name
    )

    return database, temporary_file.name


# ============================================================
# DATABASE TESTS
# ============================================================

def test_database_initialization():
    database, database_path = create_test_database()

    try:
        assert os.path.exists(
            database_path
        )

        with database.connect() as connection:
            tables = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()

        table_names = {
            row["name"]
            for row in tables
        }

        assert "scans" in table_names
        assert "findings" in table_names
        assert "risk_scores" in table_names
        assert "users" in table_names

    finally:
        os.unlink(database_path)


def test_database_user_operations():
    database, database_path = create_test_database()

    try:
        user_id = database.add_user(
            username="testuser",
            password_hash="test-password-hash",
        )

        assert user_id is not None

        user = database.get_user_by_username(
            "testuser"
        )

        assert user is not None
        assert user["username"] == "testuser"
        assert user["is_active"] == 1

        assert database.user_exists(
            "testuser"
        ) is True

    finally:
        os.unlink(database_path)


# ============================================================
# FLASK AUTHENTICATION TESTS
# ============================================================

def test_health_endpoint_is_public():
    app.config["TESTING"] = True

    client = app.test_client()

    response = client.get(
        "/api/health"
    )

    assert response.status_code == 200


def test_dashboard_requires_login():
    app.config["TESTING"] = True

    client = app.test_client()

    with client.session_transaction() as session:
        session.clear()

    response = client.get(
        "/dashboard",
        follow_redirects=False,
    )

    assert response.status_code == 302

    assert "/login" in response.headers[
        "Location"
    ]


def test_scan_api_requires_login():
    app.config["TESTING"] = True

    client = app.test_client()

    with client.session_transaction() as session:
        session.clear()

    response = client.get(
        "/api/scans/11",
        follow_redirects=False,
    )

    assert response.status_code == 302

    assert "/login" in response.headers[
        "Location"
    ]


# ============================================================
# REPORTING TESTS
# ============================================================

def test_pdf_report_exporter_import():
    from reports.pdf_exporter import (
        PDFReportExporter,
    )

    exporter = PDFReportExporter()

    assert exporter is not None


def test_html_report_exporter_import():
    from reports.html_exporter import (
        HTMLReportExporter,
    )

    exporter = HTMLReportExporter()

    assert exporter is not None
