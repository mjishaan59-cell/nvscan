import subprocess
import tempfile
from pathlib import Path

from scanner.parser import NmapXMLParser
from scanner.target_validator import TargetValidator


class PortScanner:
    """Scan TCP ports on an authorized target."""

    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.parser = NmapXMLParser()
        self.validator = TargetValidator()

    def scan(self, target):
        """Validate target, scan TCP ports, and return structured results."""

        valid, normalized_target, error = self.validator.validate(target)

        if not valid:
            return {
                "success": False,
                "error": error,
                "hosts": [],
            }

        with tempfile.TemporaryDirectory(prefix="nvscan-ports-") as temp_dir:
            xml_file = Path(temp_dir) / "ports.xml"

            command = [
                self.nmap_path,
                "-sT",
                "-oX",
                str(xml_file),
                normalized_target,
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr.strip()
                    or "Nmap port scan failed.",
                    "hosts": [],
                }

            parsed_data = self.parser.parse_file(xml_file)

            scanned_hosts = []

            for host in parsed_data["hosts"]:
                open_ports = [
                    port
                    for port in host["ports"]
                    if port["state"] == "open"
                ]

                scanned_hosts.append(
                    {
                        "status": host["status"],
                        "addresses": host["addresses"],
                        "hostnames": host["hostnames"],
                        "open_ports": open_ports,
                    }
                )

            return {
                "success": True,
                "error": None,
                "hosts": scanned_hosts,
            }


if __name__ == "__main__":
    scanner = PortScanner()

    target = input("Enter authorized target: ").strip()

    result = scanner.scan(target)

    if not result["success"]:
        print("\n===== PORT SCAN FAILED =====")
        print(f"Reason: {result['error']}")
        raise SystemExit(1)

    print("\n===== PORT SCAN SUCCESSFUL =====")
    print(f"Hosts found: {len(result['hosts'])}")

    for host in result["hosts"]:
        print("\nHost status:", host["status"])
        print("Addresses:", host["addresses"])

        print("Open ports:")

        for port in host["open_ports"]:
            print(
                f"  {port['port']}/{port['protocol']} "
                f"{port['state']} "
                f"{port['service']}"
            )
