class FindingEngine:
    """Convert normalized scanner results into security findings."""

    def analyze(self, normalized_results):
        """Analyze normalized results and generate findings."""

        findings = []

        for result in normalized_results:
            findings.extend(self._analyze_result(result))

        return findings

    def _analyze_result(self, result):
        """Analyze one normalized result."""

        findings = []

        if result["type"] == "service":
            findings.extend(
                self._analyze_service(result)
            )

        elif result["type"] == "http_service":
            findings.extend(
                self._analyze_http(result)
            )

        elif result["type"] == "web_path":
            findings.extend(
                self._analyze_web_path(result)
            )

        return findings

    def _analyze_service(self, result):
        """Analyze network service information."""

        findings = []

        port = result.get("port")
        service = result.get("service")
        product = result.get("product")
        version = result.get("version")

        # Observation: publicly accessible HTTP service.
        if port == 80 and result.get("state") == "open":
            findings.append(
                {
                    "finding_id": "WEB-001",
                    "title": "HTTP service detected",
                    "description": (
                        "An HTTP service is exposed on TCP port 80."
                    ),
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "host": result.get("host"),
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "evidence": {
                        "source": result.get("source"),
                        "state": result.get("state"),
                    },
                    "recommendation": (
                        "Verify that the HTTP service is required "
                        "and securely configured."
                    ),
                }
            )

        # Observation: SSH service detected.
        if port == 22 and result.get("state") == "open":
            findings.append(
                {
                    "finding_id": "NET-001",
                    "title": "SSH service detected",
                    "description": (
                        "An SSH service is exposed on TCP port 22."
                    ),
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "host": result.get("host"),
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "evidence": {
                        "source": result.get("source"),
                        "state": result.get("state"),
                    },
                    "recommendation": (
                        "Verify that SSH access is required and "
                        "restrict access to trusted networks."
                    ),
                }
            )

        return findings

    def _analyze_http(self, result):
        """Analyze HTTP service information."""

        findings = []

        evidence = result.get("evidence") or {}
        status_code = evidence.get("status_code")
        headers = evidence.get("headers") or {}

        if status_code is not None:
            findings.append(
                {
                    "finding_id": "WEB-002",
                    "title": "HTTP service accessible",
                    "description": (
                        "The web service responded successfully "
                        "to an HTTP request."
                    ),
                    "severity": "INFO",
                    "confidence": "HIGH",
                    "host": result.get("host"),
                    "port": result.get("port"),
                    "service": result.get("service"),
                    "product": result.get("product"),
                    "version": result.get("version"),
                    "evidence": {
                        "status_code": status_code,
                        "server": headers.get("Server"),
                    },
                    "recommendation": (
                        "Review the web server configuration and "
                        "ensure unnecessary information is not exposed."
                    ),
                }
            )

        return findings

    def _analyze_web_path(self, result):
        """Analyze discovered web paths."""

        findings = []

        evidence = result.get("evidence") or {}

        path = evidence.get("path")
        status_code = evidence.get("status_code")

        # Only report potentially interesting accessible paths.
        if (
            status_code in {200, 204, 301, 302, 307, 308, 401, 403}
            and path != "/"
        ):
            findings.append(
                {
                    "finding_id": "WEB-003",
                    "title": "Web path discovered",
                    "description": (
                        f"The web path '{path}' responded with "
                        f"HTTP status {status_code}."
                    ),
                    "severity": "LOW",
                    "confidence": "MEDIUM",
                    "host": result.get("host"),
                    "port": result.get("port"),
                    "service": result.get("service"),
                    "product": result.get("product"),
                    "version": result.get("version"),
                    "evidence": {
                        "path": path,
                        "url": evidence.get("url"),
                        "status_code": status_code,
                    },
                    "recommendation": (
                        "Review the discovered web path and verify "
                        "that the resource should be accessible."
                    ),
                }
            )

        return findings


if __name__ == "__main__":
    engine = FindingEngine()

    sample_results = [
        {
            "source": "nmap",
            "type": "service",
            "host": "127.0.0.1",
            "hostname": "localhost",
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "product": "Apache httpd",
            "version": "2.4.63",
            "evidence": None,
        }
    ]

    findings = engine.analyze(sample_results)

    print("===== FINDINGS =====")

    for finding in findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']} | "
            f"{finding['title']}"
        )
