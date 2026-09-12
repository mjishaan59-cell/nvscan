class RiskScorer:
    """Calculate explainable risk scores for security findings."""

    SEVERITY_SCORES = {
        "INFO": 0,
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 100,
    }

    CONFIDENCE_MULTIPLIERS = {
        "LOW": 0.60,
        "MEDIUM": 0.80,
        "HIGH": 1.00,
    }

    EXPOSURE_MULTIPLIERS = {
        "LOCAL": 0.50,
        "INTERNAL": 0.75,
        "NETWORK": 1.00,
        "INTERNET": 1.25,
    }

    SERVICE_CRITICALITY = {
        "ftp": 1.10,
        "telnet": 1.25,
        "rlogin": 1.25,
        "rsh": 1.25,
        "ssh": 1.10,
        "http": 1.00,
        "https": 1.00,
        "rpcbind": 1.10,
        "nfs": 1.15,
        "nfs_acl": 1.15,
        "ipp": 0.90,
        "cups": 0.90,
        "smtp": 1.05,
        "dns": 1.00,
        "ldap": 1.10,
        "smb": 1.20,
        "microsoft-ds": 1.20,
        "rdp": 1.20,
        "mysql": 1.15,
        "postgresql": 1.15,
        "redis": 1.20,
        "mongodb": 1.20,
    }

    DEFAULT_SERVICE_CRITICALITY = 1.00

    def calculate(
        self,
        severity,
        confidence="MEDIUM",
        exposure="NETWORK",
        service=None,
    ):
        """
        Calculate a normalized risk score from 0 to 100.

        Factors:
            severity
            confidence
            exposure
            service criticality
        """

        severity = severity.upper()
        confidence = confidence.upper()
        exposure = exposure.upper()

        if severity not in self.SEVERITY_SCORES:
            raise ValueError(
                f"Invalid severity: {severity}"
            )

        if confidence not in self.CONFIDENCE_MULTIPLIERS:
            raise ValueError(
                f"Invalid confidence: {confidence}"
            )

        if exposure not in self.EXPOSURE_MULTIPLIERS:
            raise ValueError(
                f"Invalid exposure: {exposure}"
            )

        base_score = self.SEVERITY_SCORES[severity]

        confidence_multiplier = (
            self.CONFIDENCE_MULTIPLIERS[confidence]
        )

        exposure_multiplier = (
            self.EXPOSURE_MULTIPLIERS[exposure]
        )

        service_name = (
            str(service).lower()
            if service is not None
            else None
        )

        service_multiplier = self.SERVICE_CRITICALITY.get(
            service_name,
            self.DEFAULT_SERVICE_CRITICALITY,
        )

        score = (
            base_score
            * confidence_multiplier
            * exposure_multiplier
            * service_multiplier
        )

        score = min(round(score, 2), 100)

        return score

    def priority(self, score):
        """Convert a numeric score into a priority level."""

        if not 0 <= score <= 100:
            raise ValueError(
                "Risk score must be between 0 and 100."
            )

        if score >= 90:
            return "CRITICAL"

        if score >= 70:
            return "HIGH"

        if score >= 40:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "INFO"

    def score_finding(
        self,
        finding,
        exposure="NETWORK",
    ):
        """Add risk information to a security finding."""

        score = self.calculate(
            severity=finding.get(
                "severity",
                "INFO",
            ),
            confidence=finding.get(
                "confidence",
                "MEDIUM",
            ),
            exposure=exposure,
            service=finding.get("service"),
        )

        priority = self.priority(score)

        result = dict(finding)

        result["risk"] = {
            "score": score,
            "priority": priority,
            "exposure": exposure.upper(),
            "service_criticality": self.SERVICE_CRITICALITY.get(
                str(finding.get("service")).lower()
                if finding.get("service") is not None
                else None,
                self.DEFAULT_SERVICE_CRITICALITY,
            ),
        }

        return result


if __name__ == "__main__":
    scorer = RiskScorer()

    test_cases = [
        {
            "name": "INFO HTTP",
            "severity": "INFO",
            "confidence": "HIGH",
            "exposure": "NETWORK",
            "service": "http",
        },
        {
            "name": "MEDIUM FTP",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "exposure": "NETWORK",
            "service": "ftp",
        },
        {
            "name": "MEDIUM NFS",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "exposure": "NETWORK",
            "service": "nfs",
        },
        {
            "name": "HIGH SSH",
            "severity": "HIGH",
            "confidence": "HIGH",
            "exposure": "NETWORK",
            "service": "ssh",
        },
        {
            "name": "HIGH Telnet",
            "severity": "HIGH",
            "confidence": "HIGH",
            "exposure": "NETWORK",
            "service": "telnet",
        },
        {
            "name": "CRITICAL SMB",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "exposure": "INTERNET",
            "service": "smb",
        },
    ]

    print("===== RISK ENGINE TEST =====")

    for case in test_cases:
        score = scorer.calculate(
            severity=case["severity"],
            confidence=case["confidence"],
            exposure=case["exposure"],
            service=case["service"],
        )

        priority = scorer.priority(score)

        print(
            f"{case['name']:<16} | "
            f"Score: {score:>6.2f} | "
            f"Priority: {priority}"
        )
