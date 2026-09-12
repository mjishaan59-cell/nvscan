from scanner.detection_rules import DetectionRules


class FindingEngine:
    """Convert normalized scanner results into security findings."""

    def __init__(self):
        self.rules = DetectionRules()

    def analyze(self, normalized_results):
        """Analyze normalized results and generate findings."""

        findings = []

        for result in normalized_results:
            findings.extend(
                self._analyze_result(result)
            )

        return self._remove_duplicates(findings)

    def _analyze_result(self, result):
        """Analyze one normalized result."""

        result_type = result.get("type")

        if result_type == "service":
            return self.rules.analyze_service(result)

        if result_type == "http_service":
            return self.rules.analyze_http(result)

        if result_type == "web_path":
            return self.rules.analyze_web_path(result)

        return []

    def _remove_duplicates(self, findings):
        """Remove duplicate findings while preserving order."""

        unique_findings = []
        seen = set()

        for finding in findings:
            evidence = finding.get("evidence") or {}

            key = (
                finding.get("finding_id"),
                finding.get("host"),
                finding.get("port"),
                finding.get("service"),
                str(sorted(evidence.items())),
            )

            if key in seen:
                continue

            seen.add(key)
            unique_findings.append(finding)

        return unique_findings


if __name__ == "__main__":
    engine = FindingEngine()

    sample_results = [
        {
            "source": "nmap",
            "type": "service",
            "host": "127.0.0.1",
            "hostname": "localhost",
            "port": 21,
            "protocol": "tcp",
            "state": "open",
            "service": "ftp",
            "product": "vsftpd",
            "version": "3.0.5",
            "evidence": None,
        },
        {
            "source": "nmap",
            "type": "service",
            "host": "127.0.0.1",
            "hostname": "localhost",
            "port": 2049,
            "protocol": "tcp",
            "state": "open",
            "service": "nfs_acl",
            "product": None,
            "version": "3",
            "evidence": None,
        },
        {
            "source": "http_scanner",
            "type": "http_service",
            "host": "http://127.0.0.1",
            "hostname": None,
            "port": None,
            "protocol": None,
            "state": "accessible",
            "service": "http",
            "product": None,
            "version": None,
            "evidence": {
                "status_code": 200,
                "content_length": 139,
                "headers": {
                    "Server": "Apache/2.4.63",
                },
            },
        },
        {
            "source": "directory_enum",
            "type": "web_path",
            "host": "http://127.0.0.1",
            "hostname": None,
            "port": None,
            "protocol": "http",
            "state": "accessible",
            "service": "http",
            "product": None,
            "version": None,
            "evidence": {
                "path": "/admin",
                "url": "http://127.0.0.1/admin",
                "status_code": 403,
                "content_length": 196,
                "redirected": False,
                "error": None,
            },
        },
    ]

    findings = engine.analyze(sample_results)

    print("===== FINDING ENGINE TEST =====")
    print(f"Findings generated: {len(findings)}")

    for finding in findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']} | "
            f"{finding['confidence']} | "
            f"{finding['title']}"
        )
