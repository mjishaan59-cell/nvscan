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

        Formula:

            score =
                base severity
                × confidence multiplier
                × exposure multiplier
                × service criticality

        The final value is capped at 100.
        """

        severity = severity.upper()
        confidence = confidence.upper()
        exposure = exposure.upper()

        self._validate_inputs(
            severity,
            confidence,
            exposure,
        )

        base_score = self.SEVERITY_SCORES[severity]

        confidence_multiplier = (
            self.CONFIDENCE_MULTIPLIERS[confidence]
        )

        exposure_multiplier = (
            self.EXPOSURE_MULTIPLIERS[exposure]
        )

        service_name = self._normalize_service(
            service
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

        return min(round(score, 2), 100)

    def explain(
        self,
        severity,
        confidence="MEDIUM",
        exposure="NETWORK",
        service=None,
    ):
        """
        Return a detailed explanation of the risk calculation.

        The returned dictionary is designed to be stored in a
        finding result and displayed in the dashboard/report.
        """

        severity = severity.upper()
        confidence = confidence.upper()
        exposure = exposure.upper()

        self._validate_inputs(
            severity,
            confidence,
            exposure,
        )

        base_score = self.SEVERITY_SCORES[severity]

        confidence_multiplier = (
            self.CONFIDENCE_MULTIPLIERS[confidence]
        )

        exposure_multiplier = (
            self.EXPOSURE_MULTIPLIERS[exposure]
        )

        service_name = self._normalize_service(
            service
        )

        service_multiplier = self.SERVICE_CRITICALITY.get(
            service_name,
            self.DEFAULT_SERVICE_CRITICALITY,
        )

        raw_score = (
            base_score
            * confidence_multiplier
            * exposure_multiplier
            * service_multiplier
        )

        final_score = min(
            round(raw_score, 2),
            100,
        )

        priority = self.priority(final_score)

        return {
            "severity": severity,
            "base_score": base_score,
            "confidence": confidence,
            "confidence_multiplier": confidence_multiplier,
            "exposure": exposure,
            "exposure_multiplier": exposure_multiplier,
            "service": service_name,
            "service_criticality": service_multiplier,
            "raw_score": round(raw_score, 2),
            "score": final_score,
            "priority": priority,
            "formula": (
                f"{base_score} × "
                f"{confidence_multiplier} × "
                f"{exposure_multiplier} × "
                f"{service_multiplier} = "
                f"{final_score}"
            ),
        }

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
        """
        Add risk information and calculation explanation
        to a security finding.
        """

        severity = finding.get(
            "severity",
            "INFO",
        )

        confidence = finding.get(
            "confidence",
            "MEDIUM",
        )

        service = finding.get("service")

        explanation = self.explain(
            severity=severity,
            confidence=confidence,
            exposure=exposure,
            service=service,
        )

        result = dict(finding)

        result["risk"] = explanation

        return result

    def _normalize_service(self, service):
        """Normalize a service name for criticality lookup."""

        if service is None:
            return None

        service = str(service).strip().lower()

        if not service:
            return None

        return service

    def _validate_inputs(
        self,
        severity,
        confidence,
        exposure,
    ):
        """Validate risk scoring inputs."""

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


if __name__ == "__main__":
    scorer = RiskScorer()

    print("===== RISK EXPLANATION TEST =====")

    explanation = scorer.explain(
        severity="MEDIUM",
        confidence="HIGH",
        exposure="NETWORK",
        service="nfs",
    )

    print()
    print("Finding: NFS service exposed")
    print()
    print("Severity:", explanation["severity"])
    print("Base Score:", explanation["base_score"])
    print(
        "Confidence:",
        explanation["confidence"],
    )
    print(
        "Confidence Multiplier:",
        explanation["confidence_multiplier"],
    )
    print(
        "Exposure:",
        explanation["exposure"],
    )
    print(
        "Exposure Multiplier:",
        explanation["exposure_multiplier"],
    )
    print(
        "Service:",
        explanation["service"],
    )
    print(
        "Service Criticality:",
        explanation["service_criticality"],
    )
    print(
        "Raw Score:",
        explanation["raw_score"],
    )
    print(
        "Final Risk Score:",
        explanation["score"],
    )
    print(
        "Priority:",
        explanation["priority"],
    )
    print(
        "Formula:",
        explanation["formula"],
    )

    print()
    print("===== SCORE FINDING TEST =====")

    finding = {
        "finding_id": "NET-007",
        "title": "NFS service exposed",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "service": "nfs",
    }

    scored_finding = scorer.score_finding(
        finding
    )

    print(
        "Finding:",
        scored_finding["finding_id"],
    )
    print(
        "Risk:",
        scored_finding["risk"],
    )
