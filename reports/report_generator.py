from collections import Counter


class ReportGenerator:
    """Generate structured security assessment reports."""

    def generate(self, scan_result):
        """Generate a report from stored scan results."""

        if not scan_result:
            raise ValueError("Scan result is required.")

        scan = scan_result.get("scan") or {}
        hosts = scan_result.get("hosts") or []
        services = scan_result.get("services") or []
        findings = scan_result.get("findings") or []

        severity_summary = self._severity_summary(findings)
        priority_summary = self._priority_summary(findings)
        risk_summary = self._risk_summary(findings)
        recommendations = self._recommendations(findings)

        return {
            "report": {
                "title": "nvscan Security Assessment Report",
                "scan_id": scan.get("id"),
                "target": scan.get("target"),
                "target_type": scan.get("target_type"),
                "status": scan.get("status"),
                "started_at": scan.get("started_at"),
                "completed_at": scan.get("completed_at"),
            },
            "executive_summary": self._executive_summary(
                scan,
                hosts,
                services,
                findings,
            ),
            "statistics": {
                "hosts": len(hosts),
                "services": len(services),
                "findings": len(findings),
                "severity": severity_summary,
                "priority": priority_summary,
                "risk": risk_summary,
            },
            "hosts": hosts,
            "services": services,
            "findings": findings,
            "recommendations": recommendations,
            "conclusion": self._conclusion(findings),
        }

    def _executive_summary(self, scan, hosts, services, findings):
        """Create the executive summary."""

        target = scan.get("target", "Unknown")

        finding_count = len(findings)
        host_count = len(hosts)
        service_count = len(services)

        if finding_count == 0:
            assessment = (
                "No security findings were generated "
                "during this assessment."
            )
        else:
            assessment = (
                f"The assessment generated "
                f"{finding_count} security finding(s) "
                f"requiring review."
            )

        return {
            "summary": (
                f"nvscan assessed target {target}. "
                f"The scan identified {host_count} host(s) "
                f"and {service_count} service(s). "
                f"{assessment}"
            ),
            "target": target,
            "hosts": host_count,
            "services": service_count,
            "findings": finding_count,
        }

    def _severity_summary(self, findings):
        """Count findings by severity."""

        counter = Counter(
            finding.get("severity", "UNKNOWN")
            for finding in findings
        )

        levels = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ]

        return {
            level: counter.get(level, 0)
            for level in levels
        }

    def _priority_summary(self, findings):
        """Count findings by risk priority."""

        counter = Counter(
            finding.get("priority", "INFO")
            for finding in findings
        )

        levels = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ]

        return {
            level: counter.get(level, 0)
            for level in levels
        }

    def _risk_summary(self, findings):
        """Calculate overall risk information."""

        scores = []

        for finding in findings:
            score = finding.get("score")

            if score is not None:
                try:
                    scores.append(float(score))
                except (TypeError, ValueError):
                    continue

        if not scores:
            return {
                "average_score": 0,
                "maximum_score": 0,
                "minimum_score": 0,
            }

        return {
            "average_score": round(
                sum(scores) / len(scores),
                2,
            ),
            "maximum_score": max(scores),
            "minimum_score": min(scores),
        }

    def _recommendations(self, findings):
        """Create a unique list of recommendations."""

        recommendations = []

        for finding in findings:
            recommendation = finding.get("recommendation")

            if (
                recommendation
                and recommendation not in recommendations
            ):
                recommendations.append(recommendation)

        return recommendations

    def _conclusion(self, findings):
        """Generate the report conclusion."""

        if not findings:
            return (
                "The assessment did not identify any findings "
                "using the currently implemented nvscan detection "
                "rules. Additional scans and broader detection "
                "rules may identify additional security issues."
            )

        critical = sum(
            1
            for finding in findings
            if finding.get("priority") == "CRITICAL"
        )

        high = sum(
            1
            for finding in findings
            if finding.get("priority") == "HIGH"
        )

        if critical > 0:
            return (
                "The assessment identified critical risk findings. "
                "These issues should be reviewed and remediated "
                "as a priority."
            )

        if high > 0:
            return (
                "The assessment identified high-risk findings. "
                "These issues should be reviewed and remediated "
                "promptly."
            )

        return (
            "The assessment identified findings that should be "
            "reviewed according to their severity, confidence, "
            "and risk priority."
        )


if __name__ == "__main__":
    print("ReportGenerator module loaded successfully.")
