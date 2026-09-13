import json
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "nvscan.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


class Database:
    """SQLite database interface for IntelliScan."""

    def __init__(self, database_path=DATABASE_PATH):
        self.database_path = Path(database_path)
        self.initialize()

    def connect(self):
        """Create and return a SQLite database connection."""

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    def initialize(self):
        """Create database tables and apply required migrations."""

        with open(
            SCHEMA_PATH,
            "r",
            encoding="utf-8",
        ) as schema_file:
            schema = schema_file.read()

        with self.connect() as connection:
            connection.executescript(schema)
            self._apply_migrations(connection)

    def _apply_migrations(self, connection):
        """Apply safe schema migrations for existing databases."""

        columns = connection.execute(
            """
            PRAGMA table_info(findings)
            """
        ).fetchall()

        column_names = {
            column["name"]
            for column in columns
        }

        if "remediation" not in column_names:
            connection.execute(
                """
                ALTER TABLE findings
                ADD COLUMN remediation TEXT
                """
            )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    # ------------------------------------------------------------------
    # Authentication / User Management
    # ------------------------------------------------------------------

    def add_user(
        self,
        username,
        password_hash,
        is_active=True,
    ):
        """Create a new application user."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    is_active
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    1 if is_active else 0,
                ),
            )

            return cursor.lastrowid

    def get_user_by_username(self, username):
        """Retrieve an application user by username."""

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    is_active,
                    created_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

            return dict(row) if row else None

    def get_user(self, user_id):
        """Retrieve an application user by ID."""

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash,
                    is_active,
                    created_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

            return dict(row) if row else None

    def user_exists(self, username):
        """Return True when a username already exists."""

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT id
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

            return row is not None

    # ------------------------------------------------------------------
    # Target Management
    # ------------------------------------------------------------------

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

            return [
                dict(row)
                for row in rows
            ]

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
                "scans": [
                    dict(scan)
                    for scan in scans
                ],
            }

    # ------------------------------------------------------------------
    # Scan Management
    # ------------------------------------------------------------------

    def add_scan(
        self,
        target_id,
        status="running",
    ):
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
                (
                    target_id,
                    status,
                ),
            )

            return cursor.lastrowid

    def update_scan_status(
        self,
        scan_id,
        status,
    ):
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
                (
                    status,
                    status,
                    scan_id,
                ),
            )

    def get_all_scans(self):
        """
        Retrieve all scans for the scan history page.

        Each scan includes the associated target information
        and the number of findings discovered during that scan.
        """

        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    scans.id,
                    scans.target_id,
                    scans.status,
                    scans.started_at,
                    scans.completed_at,
                    targets.target,
                    targets.target_type,
                    COUNT(findings.id) AS finding_count
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

            return [
                dict(row)
                for row in rows
            ]

    # ------------------------------------------------------------------
    # Host Management
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Service Management
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

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
        remediation=None,
    ):
        """Store a security finding and remediation guidance."""

        if evidence is not None:
            evidence = json.dumps(
                evidence,
                default=str,
            )

        if remediation is not None:
            remediation = json.dumps(
                remediation,
                default=str,
            )

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
                    recommendation,
                    remediation
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?
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
                    remediation,
                ),
            )

            return cursor.lastrowid

    # ------------------------------------------------------------------
    # Risk Scoring
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # JSON / Finding Decoding
    # ------------------------------------------------------------------

    def _decode_json_field(self, value):
        """Decode a JSON database field safely."""

        if value is None:
            return None

        if isinstance(
            value,
            (dict, list),
        ):
            return value

        try:
            return json.loads(value)

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return value

    def _decode_finding(self, finding):
        """Convert database finding fields back into Python objects."""

        finding = dict(finding)

        finding["evidence"] = (
            self._decode_json_field(
                finding.get("evidence")
            )
        )

        finding["remediation"] = (
            self._decode_json_field(
                finding.get("remediation")
            )
        )

        return finding

    # ------------------------------------------------------------------
    # Scan Results
    # ------------------------------------------------------------------

    def get_scan_results(
        self,
        scan_id,
    ):
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

            decoded_findings = [
                self._decode_finding(
                    finding
                )
                for finding in findings
            ]

            return {
                "scan": dict(scan),
                "hosts": [
                    dict(host)
                    for host in hosts
                ],
                "services": [
                    dict(service)
                    for service in services
                ],
                "findings": decoded_findings,
            }

    # ------------------------------------------------------------------
    # Target Scan History
    # ------------------------------------------------------------------

    def get_target_scans(
        self,
        target_id,
    ):
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

            return [
                dict(row)
                for row in rows
            ]

    # ------------------------------------------------------------------
    # Historical Comparison
    # ------------------------------------------------------------------

    def get_previous_completed_scan(
        self,
        scan_id,
    ):
        """Retrieve the previous completed scan for the same target."""

        with self.connect() as connection:

            current_scan = connection.execute(
                """
                SELECT
                    id,
                    target_id
                FROM scans
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()

            if current_scan is None:
                return None

            previous_scan = connection.execute(
                """
                SELECT *
                FROM scans
                WHERE target_id = ?
                  AND id < ?
                  AND status = 'completed'
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    current_scan["target_id"],
                    scan_id,
                ),
            ).fetchone()

            return (
                dict(previous_scan)
                if previous_scan
                else None
            )

    def get_scan_findings_for_comparison(
        self,
        scan_id,
    ):
        """Retrieve findings with their risk information for comparison."""

        with self.connect() as connection:

            rows = connection.execute(
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
                ORDER BY findings.id
                """,
                (scan_id,),
            ).fetchall()

            return [
                self._decode_finding(row)
                for row in rows
            ]

    def get_scan_services_for_comparison(
        self,
        scan_id,
    ):
        """Retrieve discovered services for comparison."""

        with self.connect() as connection:

            rows = connection.execute(
                """
                SELECT
                    services.*,
                    hosts.address,
                    hosts.hostname
                FROM services
                JOIN hosts
                    ON services.host_id = hosts.id
                WHERE hosts.scan_id = ?
                ORDER BY
                    hosts.address,
                    services.port,
                    services.protocol
                """,
                (scan_id,),
            ).fetchall()

            return [
                dict(row)
                for row in rows
            ]


if __name__ == "__main__":
    database = Database()

    print(
        "===== DATABASE INITIALIZED ====="
    )

    print(
        f"Database: "
        f"{database.database_path}"
    )

    print(
        "\n===== REGISTERED TARGETS ====="
    )

    targets = database.get_all_targets()

    if not targets:
        print(
            "No targets registered."
        )

    else:
        for target in targets:

            print(
                f"ID: {target['id']} | "
                f"Target: {target['target']} | "
                f"Type: {target['target_type']} | "
                f"Scans: {target['scan_count']}"
            )
