class DetectionRules:
    """Security detection rules for normalized nvscan results."""

    DANGEROUS_SERVICES = {
        "ftp": {
            "finding_id": "NET-002",
            "title": "FTP service exposed",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "recommendation": (
                "Disable FTP if it is not required. "
                "If file transfer is necessary, prefer a secure "
                "alternative such as SFTP or FTPS."
            ),
        },
        "telnet": {
            "finding_id": "NET-003",
            "title": "Telnet service exposed",
            "severity": "HIGH",
            "confidence": "HIGH",
            "recommendation": (
                "Disable Telnet and use SSH for secure remote "
                "administration."
            ),
        },
        "rlogin": {
            "finding_id": "NET-004",
            "title": "Rlogin service exposed",
            "severity": "HIGH",
            "confidence": "HIGH",
            "recommendation": (
                "Disable rlogin and use a secure remote "
                "administration protocol such as SSH."
            ),
        },
        "rsh": {
            "finding_id": "NET-005",
            "title": "RSH service exposed",
            "severity": "HIGH",
            "confidence": "HIGH",
            "recommendation": (
                "Disable RSH because it does not provide "
                "secure encrypted remote administration."
            ),
        },
    }

    SENSITIVE_SERVICES = {
        "rpcbind": {
            "finding_id": "NET-006",
            "title": "RPC service exposed",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "recommendation": (
                "Restrict RPC access to trusted hosts and verify "
                "that RPC services are required."
            ),
        },
        "nfs": {
            "finding_id": "NET-007",
            "title": "NFS service exposed",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "recommendation": (
                "Restrict NFS access to trusted networks and verify "
                "that exported resources do not expose sensitive data."
            ),
        },
        "nfs_acl": {
            "finding_id": "NET-007",
            "title": "NFS service exposed",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "recommendation": (
                "Restrict NFS access to trusted networks and verify "
                "that exported resources do not expose sensitive data."
            ),
        },
        "cups": {
            "finding_id": "NET-008",
            "title": "Printing service exposed",
            "severity": "LOW",
            "confidence": "HIGH",
            "recommendation": (
                "Restrict the printing service to trusted networks "
                "and disable remote access if it is not required."
            ),
        },
        "ipp": {
            "finding_id": "NET-008",
            "title": "Printing service exposed",
            "severity": "LOW",
            "confidence": "HIGH",
            "recommendation": (
                "Restrict the printing service to trusted networks "
                "and disable remote access if it is not required."
            ),
        },
    }

    SENSITIVE_WEB_PATHS = {
        "/admin": {
            "finding_id": "WEB-004",
            "title": "Administrative web path exposed",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "recommendation": (
                "Verify that the administrative interface is required "
                "and restrict it with strong authentication and "
                "network access controls."
            ),
        },
        "/backup": {
            "finding_id": "WEB-005",
            "title": "Potential backup path exposed",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "recommendation": (
                "Verify that backup files are not publicly accessible. "
                "Remove unnecessary backup resources from the web root."
            ),
        },
        "/uploads": {
            "finding_id": "WEB-006",
            "title": "Upload directory exposed",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "recommendation": (
                "Review the upload directory permissions and ensure "
                "uploaded files cannot be executed as server-side code."
            ),
        },
        "/api": {
            "finding_id": "WEB-007",
            "title": "API endpoint discovered",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "recommendation": (
                "Review the API endpoint and ensure authentication, "
                "authorization, and input validation are properly enforced."
            ),
        },
        "/login": {
            "finding_id": "WEB-008",
            "title": "Login endpoint discovered",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "recommendation": (
                "Review the login endpoint for strong authentication, "
                "rate limiting, and secure session management."
            ),
        },
    }

    HTTP_SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "finding_id": "WEB-009",
            "title": "Missing HSTS security header",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "recommendation": (
                "Enable Strict-Transport-Security when the application "
                "is served securely over HTTPS."
            ),
        },
        "Content-Security-Policy": {
            "finding_id": "WEB-010",
            "title": "Missing Content-Security-Policy header",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "recommendation": (
                "Define an appropriate Content-Security-Policy to "
                "reduce the impact of content injection and XSS attacks."
            ),
        },
        "X-Frame-Options": {
            "finding_id": "WEB-011",
            "title": "Missing clickjacking protection header",
            "severity": "LOW",
            "confidence": "HIGH",
            "recommendation": (
                "Configure X-Frame-Options or an appropriate "
                "frame-ancestors Content-Security-Policy directive."
            ),
        },
        "X-Content-Type-Options": {
            "finding_id": "WEB-012",
            "title": "Missing MIME sniffing protection header",
            "severity": "LOW",
            "confidence": "HIGH",
            "recommendation": (
                "Set X-Content-Type-Options to 'nosniff' to reduce "
                "MIME type sniffing risks."
            ),
        },
        "Referrer-Policy": {
            "finding_id": "WEB-013",
            "title": "Missing Referrer-Policy header",
            "severity": "LOW",
            "confidence": "HIGH",
            "recommendation": (
                "Configure a restrictive Referrer-Policy appropriate "
                "for the application."
            ),
        },
    }

    def analyze_service(self, result):
        """Generate findings from a normalized network service."""

        findings = []

        service = (
            result.get("service") or ""
        ).lower()

        state = result.get("state")

        if state != "open":
            return findings

        rule = self.DANGEROUS_SERVICES.get(service)

        if rule is None:
            rule = self.SENSITIVE_SERVICES.get(service)

        if rule is not None:
            findings.append(
                self._build_finding(
                    rule=rule,
                    result=result,
                    description=(
                        f"The {service} service is exposed on "
                        f"TCP port {result.get('port')}."
                    ),
                    evidence={
                        "source": result.get("source"),
                        "port": result.get("port"),
                        "protocol": result.get("protocol"),
                        "service": result.get("service"),
                        "product": result.get("product"),
                        "version": result.get("version"),
                        "state": state,
                    },
                )
            )

        return findings

    def analyze_http(self, result):
        """Generate findings from normalized HTTP information."""

        findings = []

        evidence = result.get("evidence") or {}

        headers = evidence.get("headers") or {}

        normalized_headers = {
            str(name).lower(): value
            for name, value in headers.items()
        }

        for header_name, rule in self.HTTP_SECURITY_HEADERS.items():
            if header_name.lower() not in normalized_headers:
                findings.append(
                    self._build_finding(
                        rule=rule,
                        result=result,
                        description=(
                            f"The HTTP response does not contain "
                            f"the recommended {header_name} security header."
                        ),
                        evidence={
                            "source": result.get("source"),
                            "url": result.get("host"),
                            "status_code": evidence.get(
                                "status_code"
                            ),
                            "missing_header": header_name,
                        },
                    )
                )

        server_header = normalized_headers.get("server")

        if server_header:
            findings.append(
                {
                    "finding_id": "WEB-014",
                    "title": "Web server information disclosed",
                    "description": (
                        "The HTTP response exposes web server "
                        "information through the Server header."
                    ),
                    "severity": "LOW",
                    "confidence": "HIGH",
                    "host": result.get("host"),
                    "port": result.get("port"),
                    "service": result.get("service"),
                    "product": result.get("product"),
                    "version": result.get("version"),
                    "evidence": {
                        "source": result.get("source"),
                        "server_header": server_header,
                        "status_code": evidence.get(
                            "status_code"
                        ),
                    },
                    "recommendation": (
                        "Minimize unnecessary web server version "
                        "disclosure where practical."
                    ),
                }
            )

        return findings

    def analyze_web_path(self, result):
        """Generate findings from normalized web path information."""

        findings = []

        evidence = result.get("evidence") or {}

        path = evidence.get("path")
        status_code = evidence.get("status_code")

        if path is None:
            return findings

        rule = self.SENSITIVE_WEB_PATHS.get(
            path.rstrip("/") or "/"
        )

        if rule is None:
            return findings

        if status_code not in {
            200,
            204,
            301,
            302,
            307,
            308,
            401,
            403,
        }:
            return findings

        findings.append(
            self._build_finding(
                rule=rule,
                result=result,
                description=(
                    f"The potentially sensitive web path "
                    f"'{path}' responded with HTTP status "
                    f"{status_code}."
                ),
                evidence={
                    "source": result.get("source"),
                    "path": path,
                    "url": evidence.get("url"),
                    "status_code": status_code,
                },
            )
        )

        return findings

    def _build_finding(
        self,
        rule,
        result,
        description,
        evidence,
    ):
        """Build a finding using a detection rule."""

        return {
            "finding_id": rule["finding_id"],
            "title": rule["title"],
            "description": description,
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "host": result.get("host"),
            "port": result.get("port"),
            "service": result.get("service"),
            "product": result.get("product"),
            "version": result.get("version"),
            "evidence": evidence,
            "recommendation": rule["recommendation"],
        }


if __name__ == "__main__":
    rules = DetectionRules()

    sample_service = {
        "source": "nmap",
        "type": "service",
        "host": "127.0.0.1",
        "port": 21,
        "protocol": "tcp",
        "state": "open",
        "service": "ftp",
        "product": "vsftpd",
        "version": "3.0.5",
    }

    findings = rules.analyze_service(sample_service)

    print("===== DETECTION RULE TEST =====")

    for finding in findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']} | "
            f"{finding['title']}"
        )
