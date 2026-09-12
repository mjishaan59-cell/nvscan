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

    def calculate(
        self,
        severity,
        confidence="MEDIUM",
        exposure="NETWORK",
    ):
        """Calculate a normalized risk score from 0 to 100."""

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

        score = (
            base_score
            * confidence_multiplier
            * exposure_multiplier
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
            severity=finding.get("severity", "INFO"),
            confidence=finding.get(
                "confidence",
                "MEDIUM",
            ),
            exposure=exposure,
        )

        priority = self.priority(score)

        result = dict(finding)

        result["risk"] = {
            "score": score,
            "priority": priority,
            "exposure": exposure.upper(),
        }

        return result


if __name__ == "__main__":
    scorer = RiskScorer()

    test_cases = [
        ("INFO", "HIGH", "NETWORK"),
        ("LOW", "HIGH", "NETWORK"),
        ("MEDIUM", "HIGH", "NETWORK"),
        ("HIGH", "HIGH", "NETWORK"),
        ("CRITICAL", "HIGH", "NETWORK"),
    ]

    print("===== RISK ENGINE TEST =====")

    for severity, confidence, exposure in test_cases:
        score = scorer.calculate(
            severity,
            confidence,
            exposure,
        )

        priority = scorer.priority(score)

        print(
            f"{severity:8} | "
            f"{confidence:6} | "
            f"{exposure:8} | "
            f"Score: {score:6} | "
            f"Priority: {priority}"
        )
