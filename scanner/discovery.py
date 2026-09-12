import subprocess
import tempfile
from pathlib import Path

from scanner.parser import NmapXMLParser
from scanner.target_validator import TargetValidator


class HostDiscovery:
    """Discover live hosts using Nmap."""

    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.parser = NmapXMLParser()
        self.validator = TargetValidator()

    def discover(self, target):
        """Validate a target and discover live hosts."""

        # Validate target before passing it to Nmap.
        valid, normalized_target, error = self.validator.validate(target)

        if not valid:
            return {
                "success": False,
                "error": error,
                "hosts": [],
            }

        with tempfile.TemporaryDirectory(prefix="nvscan-discovery-") as temp_dir:
            xml_file = Path(temp_dir) / "discovery.xml"

            command = [
                self.nmap_path,
                "-sn",
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
                    or "Nmap host discovery failed.",
                    "hosts": [],
                }

            parsed_data = self.parser.parse_file(xml_file)

            live_hosts = []

            for host in parsed_data["hosts"]:
                if host["status"] == "up":
                    live_hosts.append(host)

            return {
                "success": True,
                "error": None,
                "hosts": live_hosts,
            }


if __name__ == "__main__":
    discovery = HostDiscovery()

    target = input("Enter authorized target: ").strip()

    result = discovery.discover(target)

    if not result["success"]:
        print("\n===== DISCOVERY FAILED =====")
        print(f"Reason: {result['error']}")
        raise SystemExit(1)

    print("\n===== HOST DISCOVERY SUCCESSFUL =====")
    print(f"Live hosts found: {len(result['hosts'])}")

    for host in result["hosts"]:
        print("\nHost status:", host["status"])
        print("Addresses:", host["addresses"])
        print("Hostnames:", host["hostnames"])
