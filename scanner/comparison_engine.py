from database.database import Database


class ComparisonEngine:
    """Compare two completed IntelliScan scans."""

    def __init__(self, database=None):
        self.database = database or Database()

    @staticmethod
    def finding_key(finding):
        """
        Build a stable identity for a finding.

        The identity is based on the vulnerability type/location,
        rather than the database row ID, because every scan creates
        new database IDs.
        """

        return (
            finding.get("finding_id"),
            finding.get("host"),
            finding.get("port"),
            finding.get("service"),
            finding.get("product"),
            finding.get("version"),
        )

    @staticmethod
    def service_key(service):
        """
        Build a stable identity for a discovered service.
        """

        return (
            service.get("address"),
            service.get("port"),
            service.get("protocol"),
            service.get("service"),
        )

    @staticmethod
    def calculate_risk(findings):
        """Calculate the highest risk score from a scan."""

        scores = []

        for finding in findings:
            score = finding.get("score")

            if score is not None:
                try:
                    scores.append(float(score))
                except (TypeError, ValueError):
                    continue

        if not scores:
            return 0.0

        return max(scores)

    @staticmethod
    def determine_risk_status(previous_risk, current_risk):
        """Determine whether the security posture improved or regressed."""

        if current_risk < previous_risk:
            return "IMPROVED"

        if current_risk > previous_risk:
            return "REGRESSED"

        return "UNCHANGED"

    def compare(self, previous_scan_id, current_scan_id):
        """
        Compare a previous scan with a current scan.
        """

        previous_scan = self.database.get_scan_results(
            previous_scan_id
        )

        current_scan = self.database.get_scan_results(
            current_scan_id
        )

        if previous_scan is None:
            raise ValueError(
                f"Previous scan #{previous_scan_id} was not found."
            )

        if current_scan is None:
            raise ValueError(
                f"Current scan #{current_scan_id} was not found."
            )

        previous_target_id = previous_scan["scan"]["target_id"]
        current_target_id = current_scan["scan"]["target_id"]

        if previous_target_id != current_target_id:
            raise ValueError(
                "The two scans belong to different targets."
            )

        previous_findings = (
            self.database.get_scan_findings_for_comparison(
                previous_scan_id
            )
        )

        current_findings = (
            self.database.get_scan_findings_for_comparison(
                current_scan_id
            )
        )

        previous_services = (
            self.database.get_scan_services_for_comparison(
                previous_scan_id
            )
        )

        current_services = (
            self.database.get_scan_services_for_comparison(
                current_scan_id
            )
        )

        previous_finding_map = {
            self.finding_key(finding): finding
            for finding in previous_findings
        }

        current_finding_map = {
            self.finding_key(finding): finding
            for finding in current_findings
        }

        previous_finding_keys = set(
            previous_finding_map.keys()
        )

        current_finding_keys = set(
            current_finding_map.keys()
        )

        new_finding_keys = (
            current_finding_keys
            - previous_finding_keys
        )

        resolved_finding_keys = (
            previous_finding_keys
            - current_finding_keys
        )

        persistent_finding_keys = (
            previous_finding_keys
            & current_finding_keys
        )

        new_findings = [
            current_finding_map[key]
            for key in new_finding_keys
        ]

        resolved_findings = [
            previous_finding_map[key]
            for key in resolved_finding_keys
        ]

        persistent_findings = [
            current_finding_map[key]
            for key in persistent_finding_keys
        ]

        previous_service_map = {
            self.service_key(service): service
            for service in previous_services
        }

        current_service_map = {
            self.service_key(service): service
            for service in current_services
        }

        previous_service_keys = set(
            previous_service_map.keys()
        )

        current_service_keys = set(
            current_service_map.keys()
        )

        new_service_keys = (
            current_service_keys
            - previous_service_keys
        )

        closed_service_keys = (
            previous_service_keys
            - current_service_keys
        )

        new_services = [
            current_service_map[key]
            for key in new_service_keys
        ]

        closed_services = [
            previous_service_map[key]
            for key in closed_service_keys
        ]

        previous_risk = self.calculate_risk(
            previous_findings
        )

        current_risk = self.calculate_risk(
            current_findings
        )

        risk_change = current_risk - previous_risk

        risk_status = self.determine_risk_status(
            previous_risk,
            current_risk,
        )

        return {
            "target": {
                "id": current_target_id,
                "target": current_scan["scan"]["target"],
                "target_type": current_scan["scan"][
                    "target_type"
                ],
            },

            "previous_scan": {
                "id": previous_scan_id,
                "status": previous_scan["scan"]["status"],
                "started_at": previous_scan["scan"][
                    "started_at"
                ],
                "completed_at": previous_scan["scan"][
                    "completed_at"
                ],
            },

            "current_scan": {
                "id": current_scan_id,
                "status": current_scan["scan"]["status"],
                "started_at": current_scan["scan"][
                    "started_at"
                ],
                "completed_at": current_scan["scan"][
                    "completed_at"
                ],
            },

            "findings": {
                "new": new_findings,
                "resolved": resolved_findings,
                "persistent": persistent_findings,
                "counts": {
                    "new": len(new_findings),
                    "resolved": len(resolved_findings),
                    "persistent": len(
                        persistent_findings
                    ),
                    "previous_total": len(
                        previous_findings
                    ),
                    "current_total": len(
                        current_findings
                    ),
                },
            },

            "services": {
                "new": new_services,
                "closed": closed_services,
                "counts": {
                    "previous_total": len(
                        previous_services
                    ),
                    "current_total": len(
                        current_services
                    ),
                    "new": len(new_services),
                    "closed": len(closed_services),
                },
            },

            "risk": {
                "previous": previous_risk,
                "current": current_risk,
                "change": risk_change,
                "status": risk_status,
            },
        }


if __name__ == "__main__":
    database = Database()
    engine = ComparisonEngine(database)

    print("===== HISTORICAL COMPARISON ENGINE =====")

    scans = []

    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT id
            FROM scans
            WHERE status = 'completed'
            ORDER BY id DESC
            LIMIT 2
            """
        ).fetchall()

        scans = [row["id"] for row in rows]

    if len(scans) < 2:
        print(
            "At least two completed scans are required "
            "for comparison."
        )
    else:
        current_scan_id = scans[0]
        previous_scan_id = scans[1]

        result = engine.compare(
            previous_scan_id,
            current_scan_id,
        )

        print(
            f"Previous Scan: #{previous_scan_id}"
        )

        print(
            f"Current Scan:  #{current_scan_id}"
        )

        print("\n----- FINDINGS -----")

        print(
            f"New:        "
            f"{result['findings']['counts']['new']}"
        )

        print(
            f"Resolved:   "
            f"{result['findings']['counts']['resolved']}"
        )

        print(
            f"Persistent: "
            f"{result['findings']['counts']['persistent']}"
        )

        print("\n----- SERVICES -----")

        print(
            f"New:    "
            f"{result['services']['counts']['new']}"
        )

        print(
            f"Closed: "
            f"{result['services']['counts']['closed']}"
        )

        print("\n----- RISK -----")

        print(
            f"Previous: "
            f"{result['risk']['previous']}"
        )

        print(
            f"Current:  "
            f"{result['risk']['current']}"
        )

        print(
            f"Change:   "
            f"{result['risk']['change']}"
        )

        print(
            f"Status:   "
            f"{result['risk']['status']}"
        )
