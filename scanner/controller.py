from scanner.discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detection import ServiceDetector
from scanner.normalizer import ResultNormalizer
from scanner.finding_engine import FindingEngine
from web_scanner.http_scanner import HTTPScanner
from web_scanner.directory_enum import DirectoryEnumerator
from risk_engine.scorer import RiskScorer


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

    def scan(self, target):
        """Run the complete scanning pipeline."""

        print("\n===== NVSCAN STARTED =====")
        print(f"Target: {target}")

        # -------------------------------------------------
        # 1. Host Discovery
        # -------------------------------------------------

        print("\n[1/7] Running host discovery...")

        discovery_result = self.discovery.discover(target)

        if not discovery_result["success"]:
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

        # -------------------------------------------------
        # 2. Port Scanning
        # -------------------------------------------------

        print("\n[2/7] Running port scan...")

        port_result = self.port_scanner.scan(target)

        if not port_result["success"]:
            return {
                "success": False,
                "error": port_result["error"],
                "target": target,
                "hosts": hosts,
                "normalized_results": [],
                "findings": [],
            }

        print("Port scanning complete.")

        # -------------------------------------------------
        # 3. Service Detection
        # -------------------------------------------------

        print("\n[3/7] Running service detection...")

        service_result = self.service_detector.detect(target)

        if not service_result["success"]:
            return {
                "success": False,
                "error": service_result["error"],
                "target": target,
                "hosts": hosts,
                "normalized_results": [],
                "findings": [],
            }

        print("Service detection complete.")

        # -------------------------------------------------
        # 4. HTTP and Directory Enumeration
        # -------------------------------------------------

        print("\n[4/7] Running web scanning...")

        normalized_results = []

        for host in service_result["hosts"]:

            for port in host.get("ports", []):

                if port["state"] != "open":
                    continue

                service = (port.get("service") or "").lower()

                if port["port"] == 80 or service in {
                    "http",
                    "http-alt",
                }:

                    address = None

                    for item in host.get("addresses", []):
                        if item.get("type") == "ipv4":
                            address = item.get("address")
                            break

                    if address is None and host.get("addresses"):
                        address = host["addresses"][0].get(
                            "address"
                        )

                    if address is None:
                        continue

                    http_result = self.http_scanner.scan(
                        address
                    )

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

        # -------------------------------------------------
        # 5. Normalize Nmap Results
        # -------------------------------------------------

        print("\n[5/7] Normalizing scan results...")

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

        # -------------------------------------------------
        # 6. Finding Analysis
        # -------------------------------------------------

        print("\n[6/7] Analyzing findings...")

        findings = self.finding_engine.analyze(
            normalized_results
        )

        print(
            f"Finding analysis complete: "
            f"{len(findings)} finding(s)"
        )

        # -------------------------------------------------
        # 7. Risk Scoring
        # -------------------------------------------------

        print("\n[7/7] Calculating risk scores...")

        scored_findings = []

        for finding in findings:

            scored = self.risk_scorer.score_finding(
                finding,
                exposure="NETWORK",
            )

            scored_findings.append(scored)

        print(
            f"Risk scoring complete: "
            f"{len(scored_findings)} finding(s)"
        )

        print("\n===== NVSCAN COMPLETED =====")

        return {
            "success": True,
            "error": None,
            "target": target,
            "hosts": hosts,
            "normalized_results": normalized_results,
            "findings": scored_findings,
        }


if __name__ == "__main__":
    controller = ScanController()

    target = input(
        "Enter authorized target: "
    ).strip()

    result = controller.scan(target)

    if not result["success"]:
        print("\n===== NVSCAN FAILED =====")
        print(f"Reason: {result['error']}")
        raise SystemExit(1)

    print("\n===== FINAL RESULTS =====")

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

        risk = finding.get("risk", {})

        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']} | "
            f"{finding['title']} | "
            f"Risk: {risk.get('score')} | "
            f"Priority: {risk.get('priority')}"
        )
