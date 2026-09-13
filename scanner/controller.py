from database.database import Database

from scanner.discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detection import ServiceDetector
from scanner.normalizer import ResultNormalizer
from scanner.finding_engine import FindingEngine

from web_scanner.http_scanner import HTTPScanner
from web_scanner.directory_enum import DirectoryEnumerator

from risk_engine.scorer import RiskScorer
from vulnerability_engine.correlator import CVECorrelator
from remediation_engine.engine import RemediationEngine


class ScanController:
    """Orchestrate the complete nvscan scanning pipeline."""

    def __init__(self):
        self.discovery = HostDiscovery()
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()

        self.http_scanner = HTTPScanner()
        self.directory_enumerator = DirectoryEnumerator()

        self.normalizer = ResultNormalizer()
        self.finding_engine = FindingEngine()
        self.risk_scorer = RiskScorer()
        self.cve_correlator = CVECorrelator()
        self.remediation_engine = RemediationEngine()

        self.database = Database()

        self.database.initialize()

    def scan(self, target):
        """Run the complete scanning pipeline and save results."""

        print("\n===== NVSCAN STARTED =====")
        print(f"Target: {target}")

        # 0. Create target and scan records
        target_type = self._detect_target_type(target)

        try:
            target_id = self.database.add_target(
                target,
                target_type,
            )
        except Exception as error:
            return {
                "success": False,
                "error": f"Could not create target: {error}",
                "target": target,
                "hosts": [],
                "normalized_results": [],
                "findings": [],
            }

        scan_id = self.database.add_scan(
            target_id,
            status="running",
        )

        print(f"Database target ID: {target_id}")
        print(f"Database scan ID: {scan_id}")

        # 1. Host Discovery
        print("\n[1/8] Running host discovery...")
        discovery_result = self.discovery.discover(target)

        if not discovery_result["success"]:
            self.database.update_scan_status(
                scan_id,
                "failed",
            )

            return {
                "success": False,
                "error": discovery_result["error"],
                "target": target,
                "hosts": [],
                "normalized_results": [],
                "findings": [],
            }

        hosts = discovery_result["hosts"]

        print(
            f"Host discovery complete: "
            f"{len(hosts)} live host(s)"
        )

        # 2. Port Scanning
        print("\n[2/8] Running port scan...")
        port_result = self.port_scanner.scan(target)

        if not port_result["success"]:
            self.database.update_scan_status(
                scan_id,
                "failed",
            )

            return {
                "success": False,
                "error": port_result["error"],
                "target": target,
                "hosts": hosts,
                "normalized_results": [],
                "findings": [],
            }

        print("Port scanning complete.")

        # 3. Service Detection
        print("\n[3/8] Running service detection...")
        service_result = self.service_detector.detect(target)

        if not service_result["success"]:
            self.database.update_scan_status(
                scan_id,
                "failed",
            )

            return {
                "success": False,
                "error": service_result["error"],
                "target": target,
                "hosts": hosts,
                "normalized_results": [],
                "findings": [],
            }

        print("Service detection complete.")

        # 4. HTTP and Directory Enumeration
        print("\n[4/8] Running web scanning...")
        normalized_results = []

        for host in service_result["hosts"]:
            for port in host.get("ports", []):
                if port["state"] != "open":
                    continue

                service = (
                    port.get("service") or ""
                ).lower()

                if port["port"] == 80 or service in {
                    "http",
                    "http-alt",
                }:
                    address = None

                    for item in host.get("addresses", []):
                        if item.get("type") == "ipv4":
                            address = item.get("address")
                            break

                    if (
                        address is None
                        and host.get("addresses")
                    ):
                        address = host["addresses"][0].get(
                            "address"
                        )

                    if address is None:
                        continue

                    http_result = self.http_scanner.scan(address)

                    normalized_results.extend(
                        self.normalizer.normalize_http(
                            http_result
                        )
                    )

                    directory_result = (
                        self.directory_enumerator.enumerate(
                            address
                        )
                    )

                    normalized_results.extend(
                        self.normalizer.normalize_directories(
                            directory_result
                        )
                    )

        print("Web scanning complete.")

        # 5. Normalize Nmap Results
        print("\n[5/8] Normalizing scan results...")

        for host in service_result["hosts"]:
            normalized_results.extend(
                self.normalizer.normalize_nmap(
                    {
                        "hosts": [host]
                    }
                )
            )

        print(
            f"Normalization complete: "
            f"{len(normalized_results)} result(s)"
        )

        # 6. Finding Analysis
        print("\n[6/8] Analyzing findings...")
        findings = self.finding_engine.analyze(
            normalized_results
        )

        print(
            f"Finding analysis complete: "
            f"{len(findings)} finding(s)"
        )

        # 7. CVE Correlation
        print("\n[7/8] Checking for known CVEs...")

        cve_findings = []
        seen_cves = set()

        for result in normalized_results:
            if result.get("type") != "service":
                continue

            matches = self.cve_correlator.correlate(result)

            for finding in matches:
                key = (
                    finding.get("finding_id"),
                    finding.get("host"),
                    finding.get("port"),
                    finding.get("product"),
                    finding.get("version"),
                )

                if key in seen_cves:
                    continue

                seen_cves.add(key)
                cve_findings.append(finding)

        print(
            f"CVE correlation complete: "
            f"{len(cve_findings)} CVE finding(s)"
        )

        findings.extend(cve_findings)

        print(
            f"Total findings after CVE correlation: "
            f"{len(findings)}"
        )

        # 8. Risk Scoring and Remediation
        print("\n[8/8] Calculating risk scores...")

        scored_findings = []

        for finding in findings:
            scored = self.risk_scorer.score_finding(
                finding,
                exposure="NETWORK",
            )

            remediation = self.remediation_engine.generate(
                scored
            )

            scored["remediation"] = remediation

            scored_findings.append(scored)

        print(
            f"Risk scoring complete: "
            f"{len(scored_findings)} finding(s)"
        )

        print(
            f"Remediation guidance generated for "
            f"{len(scored_findings)} finding(s)"
        )

        # 9. Save Hosts and Services
        print("\n[DB] Saving hosts and services...")

        self._save_hosts_and_services(
            scan_id,
            service_result["hosts"],
        )

        # 10. Save Findings and Risk Scores
        print("[DB] Saving findings and risk scores...")

        self._save_findings(
            scan_id,
            scored_findings,
        )

        # 11. Mark Scan Completed
        self.database.update_scan_status(
            scan_id,
            "completed",
        )

        print("\n[DB] Scan results saved successfully.")
        print("\n===== NVSCAN COMPLETED =====")

        return {
            "success": True,
            "error": None,
            "target": target,
            "scan_id": scan_id,
            "hosts": hosts,
            "normalized_results": normalized_results,
            "findings": scored_findings,
        }

    def _detect_target_type(self, target):
        """Determine a basic target type."""

        target = target.strip()

        if "/" in target:
            return "network"

        parts = target.split(".")

        if len(parts) == 4 and all(
            part.isdigit()
            for part in parts
        ):
            return "ipv4"

        if ":" in target:
            return "ipv6"

        return "hostname"

    def _save_hosts_and_services(
        self,
        scan_id,
        hosts,
    ):
        """Save discovered hosts and services."""

        for host in hosts:
            hostname = None

            if host.get("hostnames"):
                hostname = host["hostnames"][0].get(
                    "name"
                )

            for address in host.get(
                "addresses",
                [],
            ):
                host_id = self.database.add_host(
                    scan_id=scan_id,
                    address=address.get("address"),
                    address_type=address.get(
                        "type"
                    ),
                    hostname=hostname,
                    status=host.get("status"),
                )

                for port in host.get(
                    "ports",
                    [],
                ):
                    self.database.add_service(
                        host_id=host_id,
                        port=port.get("port"),
                        protocol=port.get(
                            "protocol"
                        ),
                        state=port.get("state"),
                        service=port.get(
                            "service"
                        ),
                        product=port.get(
                            "product"
                        ),
                        version=port.get(
                            "version"
                        ),
                    )

    def _save_findings(
        self,
        scan_id,
        findings,
    ):
        """Save findings and associated risk scores."""

        for finding in findings:

            risk = finding.get(
                "risk",
                {},
            )

            finding_db_id = (
                self.database.add_finding(
                    scan_id=scan_id,
                    finding_id=finding.get(
                        "finding_id"
                    ),
                    title=finding.get(
                        "title"
                    ),
                    description=finding.get(
                        "description"
                    ),
                    severity=finding.get(
                        "severity",
                        "INFO",
                    ),
                    confidence=finding.get(
                        "confidence"
                    ),
                    host=finding.get(
                        "host"
                    ),
                    port=finding.get(
                        "port"
                    ),
                    service=finding.get(
                        "service"
                    ),
                    product=finding.get(
                        "product"
                    ),
                    version=finding.get(
                        "version"
                    ),
                    evidence=finding.get(
                        "evidence"
                    ),
                    recommendation=finding.get(
                        "recommendation"
                    ),
                    remediation=finding.get(
                        "remediation"
                    ),
                )
            )

            self.database.add_risk_score(
                finding_id=finding_db_id,
                score=risk.get(
                    "score",
                    0,
                ),
                priority=risk.get(
                    "priority",
                    "INFO",
                ),
                exposure=risk.get(
                    "exposure",
                    "NETWORK",
                ),
            )


if __name__ == "__main__":
    controller = ScanController()

    target = input(
        "Enter authorized target: "
    ).strip()

    result = controller.scan(target)

    if not result["success"]:
        print("\n===== NVSCAN FAILED =====")
        print(
            f"Reason: {result['error']}"
        )
        raise SystemExit(1)

    print("\n===== FINAL RESULTS =====")

    print(
        f"Scan ID: "
        f"{result['scan_id']}"
    )

    print(
        f"Live hosts: "
        f"{len(result['hosts'])}"
    )

    print(
        f"Normalized results: "
        f"{len(result['normalized_results'])}"
    )

    print(
        f"Findings: "
        f"{len(result['findings'])}"
    )

    print("\nFindings:")

    for finding in result["findings"]:
        risk = finding.get(
            "risk",
            {},
        )

        remediation = finding.get(
            "remediation",
            {},
        )

        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']} | "
            f"{finding['title']} | "
            f"Risk: {risk.get('score')} | "
            f"Priority: {risk.get('priority')}"
        )

        if remediation:
            print(
                f"  Remediation: "
                f"{remediation.get('action')}"
            )
