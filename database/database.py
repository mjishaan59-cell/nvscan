import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "nvscan.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


class Database:
    """SQLite database interface for nvscan."""

    def __init__(self, database_path=DATABASE_PATH):
        self.database_path = Path(database_path)

    def connect(self):
        """Create and return a SQLite database connection."""

        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        return connection

    def initialize(self):
        """Create database tables from schema.sql."""

        with open(
            SCHEMA_PATH,
            "r",
            encoding="utf-8",
        ) as schema_file:
            schema = schema_file.read()

        with self.connect() as connection:
            connection.executescript(schema)

    def add_target(self, target, target_type):
        """Add a target or return the existing target ID."""

        with self.connect() as connection:
            existing = connection.execute(
                """
                SELECT id
                FROM targets
                WHERE target = ?
                """,
                (target,),
            ).fetchone()

            if existing is not None:
                return existing["id"]

            cursor = connection.execute(
                """
                INSERT INTO targets (
                    target,
                    target_type
                )
                VALUES (?, ?)
                """,
                (target, target_type),
            )

            return cursor.lastrowid

    def get_target(self, target_id):
        """Retrieve a target by ID."""

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM targets
                WHERE id = ?
                """,
                (target_id,),
            ).fetchone()

            return dict(row) if row else None

    def get_target_by_value(self, target):
        """Retrieve a target by its target value."""

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM targets
                WHERE target = ?
                """,
                (target,),
            ).fetchone()

            return dict(row) if row else None

    def get_all_targets(self):
        """Retrieve all registered targets with scan counts."""

        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    targets.id,
                    targets.target,
                    targets.target_type,
                    targets.created_at,
                    COUNT(scans.id) AS scan_count
                FROM targets
                LEFT JOIN scans
                    ON scans.target_id = targets.id
                GROUP BY
                    targets.id,
                    targets.target,
                    targets.target_type,
                    targets.created_at
                ORDER BY targets.id DESC
                """
            ).fetchall()

            return [dict(row) for row in rows]

    def get_target_details(self, target_id):
        """Retrieve a target together with its scan history."""

        with self.connect() as connection:
            target = connection.execute(
                """
                SELECT
                    targets.id,
                    targets.target,
                    targets.target_type,
                    targets.created_at,
                    COUNT(scans.id) AS scan_count
                FROM targets
                LEFT JOIN scans
                    ON scans.target_id = targets.id
                WHERE targets.id = ?
                GROUP BY
                    targets.id,
                    targets.target,
                    targets.target_type,
                    targets.created_at
                """,
                (target_id,),
            ).fetchone()

            if target is None:
                return None

            scans = connection.execute(
                """
                SELECT
                    id,
                    target_id,
                    status,
                    started_at,
                    completed_at
                FROM scans
                WHERE target_id = ?
                ORDER BY id DESC
                """,
                (target_id,),
            ).fetchall()

            return {
                "target": dict(target),
                "scans": [dict(scan) for scan in scans],
            }

    def add_scan(self, target_id, status="running"):
        """Create a new scan for a target."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    target_id,
                    status
                )
                VALUES (?, ?)
                """,
                (target_id, status),
            )

            return cursor.lastrowid

    def update_scan_status(self, scan_id, status):
        """Update the status of a scan."""

        with self.connect() as connection:
            connection.execute(
                """
                UPDATE scans
                SET
                    status = ?,
                    completed_at = CASE
                        WHEN ? IN (
                            'completed',
                            'failed'
                        )
                        THEN CURRENT_TIMESTAMP
                        ELSE completed_at
                    END
                WHERE id = ?
                """,
                (status, status, scan_id),
            )

    def add_host(
        self,
        scan_id,
        address,
        address_type=None,
        hostname=None,
        status=None,
    ):
        """Add a discovered host."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO hosts (
                    scan_id,
                    address,
                    address_type,
                    hostname,
                    status
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    address,
                    address_type,
                    hostname,
                    status,
                ),
            )

            return cursor.lastrowid

    def add_service(
        self,
        host_id,
        port,
        protocol,
        state,
        service,
        product=None,
        version=None,
    ):
        """Add a detected network service."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO services (
                    host_id,
                    port,
                    protocol,
                    state,
                    service,
                    product,
                    version
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host_id,
                    port,
                    protocol,
                    state,
                    service,
                    product,
                    version,
                ),
            )

            return cursor.lastrowid

    def add_finding(
        self,
        scan_id,
        finding_id,
        title,
        description=None,
        severity="INFO",
        confidence=None,
        host=None,
        port=None,
        service=None,
        product=None,
        version=None,
        evidence=None,
        recommendation=None,
    ):
        """Store a security finding."""

        if evidence is not None:
            evidence = json.dumps(evidence)

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO findings (
                    scan_id,
                    finding_id,
                    title,
                    description,
                    severity,
                    confidence,
                    host,
                    port,
                    service,
                    product,
                    version,
                    evidence,
                    recommendation
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?
                )
                """,
                (
                    scan_id,
                    finding_id,
                    title,
                    description,
                    severity,
                    confidence,
                    host,
                    port,
                    service,
                    product,
                    version,
                    evidence,
                    recommendation,
                ),
            )

            return cursor.lastrowid

    def add_risk_score(
        self,
        finding_id,
        score,
        priority,
        exposure,
    ):
        """Store a risk score for a finding."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO risk_scores (
                    finding_id,
                    score,
                    priority,
                    exposure
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    finding_id,
                    score,
                    priority,
                    exposure,
                ),
            )

            return cursor.lastrowid

    def get_scan_results(self, scan_id):
        """Retrieve a complete scan result."""

        with self.connect() as connection:
            scan = connection.execute(
                """
                SELECT
                    scans.*,
                    targets.target,
                    targets.target_type
                FROM scans
                JOIN targets
                    ON scans.target_id = targets.id
                WHERE scans.id = ?
                """,
                (scan_id,),
            ).fetchone()

            if scan is None:
                return None

            hosts = connection.execute(
                """
                SELECT *
                FROM hosts
                WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

            services = connection.execute(
                """
                SELECT
                    services.*,
                    hosts.address,
                    hosts.hostname
                FROM services
                JOIN hosts
                    ON services.host_id = hosts.id
                WHERE hosts.scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

            findings = connection.execute(
                """
                SELECT
                    findings.*,
                    risk_scores.score,
                    risk_scores.priority,
                    risk_scores.exposure
                FROM findings
                LEFT JOIN risk_scores
                    ON findings.id = risk_scores.finding_id
                WHERE findings.scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

            return {
                "scan": dict(scan),
                "hosts": [dict(host) for host in hosts],
                "services": [dict(service) for service in services],
                "findings": [dict(finding) for finding in findings],
            }

    def get_target_scans(self, target_id):
        """Retrieve all scans belonging to a target."""

        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM scans
                WHERE target_id = ?
                ORDER BY id DESC
                """,
                (target_id,),
            ).fetchall()

            return [dict(row) for row in rows]


if __name__ == "__main__":
    database = Database()

    database.initialize()

    print("===== DATABASE INITIALIZED =====")
    print(f"Database: {database.database_path}")

    print("\n===== REGISTERED TARGETS =====")

    targets = database.get_all_targets()

    if not targets:
        print("No targets registered.")
    else:
        for target in targets:
            print(
                f"ID: {target['id']} | "
                f"Target: {target['target']} | "
                f"Type: {target['target_type']} | "
                f"Scans: {target['scan_count']}"
            )
