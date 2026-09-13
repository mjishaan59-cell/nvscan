class RemediationEngine:
    """Generate actionable remediation guidance for security findings."""

    DEFAULT_REMEDIATION = {
        "title": "Review and remediate the security finding",
        "action": (
            "Investigate the identified security issue and apply the "
            "appropriate security controls."
        ),
        "steps": [
            "Review the finding evidence and confirm that the issue is present.",
            "Apply the recommended security configuration or software update.",
            "Restrict unnecessary network exposure.",
            "Re-run the vulnerability scan to verify the issue is resolved.",
        ],
        "verification": [
            "Re-run the IntelliScan assessment against the affected target.",
            "Confirm that the finding is no longer detected.",
            "Verify that the affected service remains available and secure.",
        ],
    }

    REMEDIATIONS = {
        "NET-002": {
            "title": "Secure or disable FTP service",
            "action": (
                "FTP transmits credentials and data insecurely in many "
                "configurations. Disable FTP when it is not required or "
                "replace it with a secure file-transfer protocol."
            ),
            "steps": [
                "Determine whether the FTP service is required.",
                "If it is not required, stop and disable the FTP service.",
                "If file transfer is required, migrate users to SFTP or another secure alternative.",
                "Restrict access to trusted hosts using the firewall.",
                "Require strong authentication and remove unnecessary anonymous access.",
            ],
            "verification": [
                "Confirm that TCP port 21 is closed if FTP was disabled.",
                "If FTP remains enabled, verify that only trusted systems can reach it.",
                "Run IntelliScan again and confirm that NET-002 is no longer reported.",
            ],
        },
        "NET-003": {
            "title": "Disable Telnet",
            "action": (
                "Telnet provides remote terminal access without modern "
                "encrypted transport. Replace it with SSH."
            ),
            "steps": [
                "Identify the Telnet service or socket providing remote access.",
                "Stop the Telnet service.",
                "Disable Telnet from starting automatically.",
                "Enable SSH for secure remote administration.",
                "Restrict SSH access with firewall rules and appropriate authentication controls.",
            ],
            "verification": [
                "Confirm that TCP port 23 is no longer exposed.",
                "Confirm that SSH is available for authorized administration.",
                "Run IntelliScan again and verify that NET-003 is resolved.",
            ],
        },
        "NET-004": {
            "title": "Disable rlogin",
            "action": (
                "Replace the legacy rlogin service with SSH and remove "
                "unnecessary remote-login exposure."
            ),
            "steps": [
                "Identify the rlogin service.",
                "Stop and disable the service.",
                "Remove unnecessary legacy remote-login configuration.",
                "Configure SSH for secure remote administration.",
                "Restrict remote administration to trusted networks.",
            ],
            "verification": [
                "Confirm that the rlogin port is closed.",
                "Verify that authorized remote administration works through SSH.",
                "Run IntelliScan again.",
            ],
        },
        "NET-005": {
            "title": "Disable rsh",
            "action": (
                "Replace the insecure rsh service with SSH and restrict "
                "remote administration."
            ),
            "steps": [
                "Identify the rsh service.",
                "Stop and disable rsh.",
                "Remove unnecessary rsh configuration.",
                "Configure SSH for secure administration.",
                "Restrict SSH access to trusted sources.",
            ],
            "verification": [
                "Confirm that the rsh service is no longer listening.",
                "Verify secure SSH access.",
                "Run IntelliScan again and confirm that NET-005 is resolved.",
            ],
        },
        "NET-006": {
            "title": "Restrict rpcbind exposure",
            "action": (
                "rpcbind can expose RPC services to untrusted networks. "
                "Disable it when unnecessary or restrict access to trusted systems."
            ),
            "steps": [
                "Determine which applications require rpcbind.",
                "Disable rpcbind if it is not required.",
                "If required, restrict access using firewall rules.",
                "Review RPC services registered with rpcbind.",
                "Expose only services required by the application.",
            ],
            "verification": [
                "Confirm that only trusted hosts can access rpcbind.",
                "Verify that required RPC-dependent applications continue to function.",
                "Run IntelliScan again.",
            ],
        },
        "NET-007": {
            "title": "Secure NFS exposure",
            "action": (
                "Review NFS exports and restrict NFS access to trusted clients."
            ),
            "steps": [
                "Review the configured NFS exports.",
                "Remove unnecessary exports.",
                "Restrict exports to approved client networks or hosts.",
                "Avoid exporting sensitive directories unnecessarily.",
                "Use appropriate filesystem permissions and, where applicable, stronger NFS security controls.",
                "Restrict NFS-related ports with the firewall.",
            ],
            "verification": [
                "Confirm that only authorized clients can access NFS.",
                "Verify that unauthorized hosts cannot mount exported resources.",
                "Run IntelliScan again.",
            ],
        },
        "NET-008": {
            "title": "Restrict or disable unnecessary CUPS exposure",
            "action": (
                "CUPS should not be unnecessarily exposed to untrusted networks."
            ),
            "steps": [
                "Determine whether network printer management is required.",
                "Disable CUPS if it is not required.",
                "If required, restrict CUPS access to trusted networks.",
                "Review printer-sharing configuration.",
                "Restrict the CUPS service using firewall controls.",
            ],
            "verification": [
                "Confirm that CUPS is not exposed to untrusted networks.",
                "Verify required printing functionality.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-004": {
            "title": "Restrict administrative web paths",
            "action": (
                "An administrative path was discovered. Restrict administrative "
                "interfaces using authentication, authorization and network controls."
            ),
            "steps": [
                "Confirm whether the administrative endpoint is intentionally exposed.",
                "Require strong authentication.",
                "Apply authorization controls so only permitted users can access it.",
                "Restrict administrative access to trusted networks where possible.",
                "Remove unnecessary administrative interfaces from production systems.",
            ],
            "verification": [
                "Request the administrative path without authentication and confirm access is denied.",
                "Test access using an authorized account.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-005": {
            "title": "Remove or protect backup files",
            "action": (
                "A backup-related web path was discovered. Backup files should "
                "not be publicly accessible."
            ),
            "steps": [
                "Identify the files or directories exposed by the backup path.",
                "Remove unnecessary backup files from the web root.",
                "Store backups outside publicly served directories.",
                "Restrict access to required backup resources.",
                "Review web-server directory permissions.",
            ],
            "verification": [
                "Request the backup path and confirm it is inaccessible.",
                "Confirm backup files are stored outside the public web root.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-006": {
            "title": "Restrict upload directories",
            "action": (
                "An upload directory was discovered. Upload locations should "
                "be strongly restricted and protected from malicious content."
            ),
            "steps": [
                "Require authentication and authorization for uploads.",
                "Validate uploaded filenames and file types.",
                "Store uploads outside executable web directories where possible.",
                "Prevent execution of uploaded scripts.",
                "Apply appropriate filesystem permissions and size limits.",
            ],
            "verification": [
                "Confirm unauthorized users cannot upload files.",
                "Confirm uploaded files cannot be executed as server-side code.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-007": {
            "title": "Review exposed API endpoint",
            "action": (
                "An API endpoint was discovered. Verify that it does not expose "
                "sensitive functionality or data without appropriate controls."
            ),
            "steps": [
                "Identify the API functionality exposed by the endpoint.",
                "Require authentication where appropriate.",
                "Apply authorization checks to sensitive operations.",
                "Validate and sanitize API input.",
                "Avoid exposing unnecessary debugging or administrative functionality.",
                "Apply rate limiting where appropriate.",
            ],
            "verification": [
                "Test unauthenticated access to sensitive API operations.",
                "Verify authorization for privileged operations.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-008": {
            "title": "Secure the login endpoint",
            "action": (
                "A login endpoint was discovered. Protect authentication "
                "against brute force, credential theft and unauthorized access."
            ),
            "steps": [
                "Require HTTPS for authentication traffic.",
                "Use strong password policies.",
                "Implement rate limiting or account lockout protections.",
                "Use secure session management.",
                "Consider multi-factor authentication for privileged accounts.",
            ],
            "verification": [
                "Confirm login traffic uses HTTPS.",
                "Verify rate limiting against repeated failed attempts.",
                "Verify secure session cookies.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-009": {
            "title": "Enable HTTP Strict Transport Security",
            "action": (
                "The HSTS security header is missing. Configure the web server "
                "or application to send Strict-Transport-Security over HTTPS."
            ),
            "steps": [
                "Ensure the application is correctly configured for HTTPS.",
                "Configure the Strict-Transport-Security response header.",
                "Start with an appropriate max-age value.",
                "After validation, consider including subdomains where appropriate.",
                "Only enable preload-related settings after confirming they are suitable for the domain.",
            ],
            "verification": [
                "Request the HTTPS endpoint.",
                "Confirm the Strict-Transport-Security header is present.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-010": {
            "title": "Implement Content Security Policy",
            "action": (
                "The Content-Security-Policy header is missing. Define a policy "
                "that restricts which content sources browsers may load."
            ),
            "steps": [
                "Identify required script, style, image and connection sources.",
                "Create a restrictive Content-Security-Policy.",
                "Test the policy for application compatibility.",
                "Remove unnecessary unsafe sources.",
                "Deploy the policy and monitor violations.",
            ],
            "verification": [
                "Inspect HTTP response headers.",
                "Confirm Content-Security-Policy is present.",
                "Verify that legitimate application functionality still works.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-011": {
            "title": "Prevent clickjacking",
            "action": (
                "The X-Frame-Options header is missing. Prevent unauthorized "
                "framing of sensitive pages."
            ),
            "steps": [
                "Configure X-Frame-Options with an appropriate policy such as SAMEORIGIN.",
                "Where supported and appropriate, also use CSP frame-ancestors.",
                "Test legitimate iframe usage before enforcing the policy.",
            ],
            "verification": [
                "Inspect the HTTP response headers.",
                "Confirm the clickjacking protection header is present.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-012": {
            "title": "Enable MIME type sniffing protection",
            "action": (
                "The X-Content-Type-Options header is missing. Configure "
                "nosniff to reduce browser MIME-sniffing risks."
            ),
            "steps": [
                "Configure the X-Content-Type-Options response header.",
                "Set the value to nosniff.",
                "Verify that the application sends correct Content-Type headers.",
            ],
            "verification": [
                "Inspect the HTTP response headers.",
                "Confirm X-Content-Type-Options: nosniff is present.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-013": {
            "title": "Configure Referrer-Policy",
            "action": (
                "The Referrer-Policy header is missing. Configure a policy "
                "that limits unnecessary referrer information."
            ),
            "steps": [
                "Choose an application-appropriate referrer policy.",
                "Configure the Referrer-Policy response header.",
                "Test navigation and analytics functionality.",
            ],
            "verification": [
                "Inspect HTTP response headers.",
                "Confirm Referrer-Policy is present.",
                "Run IntelliScan again.",
            ],
        },
        "WEB-014": {
            "title": "Reduce server version disclosure",
            "action": (
                "The HTTP Server response header reveals server information. "
                "Reduce unnecessary technology and version disclosure."
            ),
            "steps": [
                "Identify the web server header information being disclosed.",
                "Configure the server to minimize version information where supported.",
                "Avoid exposing unnecessary framework and platform details.",
                "Do not treat header hiding as a replacement for patching and hardening.",
            ],
            "verification": [
                "Inspect the HTTP response Server header.",
                "Confirm unnecessary version details are no longer exposed.",
                "Run IntelliScan again.",
            ],
        },
    }

    def generate(self, finding):
        """Generate remediation guidance for one finding."""

        if not isinstance(finding, dict):
            raise TypeError("finding must be a dictionary")

        finding_id = finding.get("finding_id")

        remediation = self.REMEDIATIONS.get(
            finding_id,
            self.DEFAULT_REMEDIATION,
        )

        result = {
            "finding_id": finding_id,
            "title": remediation["title"],
            "action": remediation["action"],
            "steps": list(remediation["steps"]),
            "verification": list(remediation["verification"]),
            "priority": finding.get(
                "priority",
                finding.get("severity", "INFO"),
            ),
        }

        if finding.get("recommendation"):
            result["action"] = finding["recommendation"]

        evidence = finding.get("evidence") or {}

        if evidence.get("cve_id"):
            result["cve_id"] = evidence["cve_id"]

        if evidence.get("cvss") is not None:
            result["cvss"] = evidence["cvss"]

        if finding.get("product"):
            result["product"] = finding["product"]

        if finding.get("version"):
            result["version"] = finding["version"]

        return result

    def generate_all(self, findings):
        """Generate remediation guidance for multiple findings."""

        if findings is None:
            return []

        return [
            self.generate(finding)
            for finding in findings
        ]


if __name__ == "__main__":
    engine = RemediationEngine()

    sample_finding = {
        "finding_id": "NET-003",
        "title": "Telnet service exposed",
        "severity": "HIGH",
        "confidence": "HIGH",
        "host": "192.168.1.10",
        "port": 23,
        "service": "telnet",
        "evidence": {
            "source": "nmap",
        },
    }

    remediation = engine.generate(sample_finding)

    print("===== REMEDIATION ENGINE TEST =====")
    print(f"Finding: {remediation['finding_id']}")
    print(f"Title: {remediation['title']}")
    print(f"Priority: {remediation['priority']}")
    print(f"Action: {remediation['action']}")

    print("\nSteps:")

    for number, step in enumerate(
        remediation["steps"],
        start=1,
    ):
        print(f"{number}. {step}")

    print("\nVerification:")

    for number, step in enumerate(
        remediation["verification"],
        start=1,
    ):
        print(f"{number}. {step}")
