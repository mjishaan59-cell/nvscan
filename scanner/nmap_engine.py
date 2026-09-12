import subprocess
import tempfile
from pathlib import Path

from scanner.parser import NmapXMLParser


class NmapScanner:
    """Run Nmap scans and return structured results."""

    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.parser = NmapXMLParser()

    def scan(self, target):
        """Run a basic TCP Nmap scan and parse the XML result."""

        with tempfile.TemporaryDirectory(prefix="nvscan-") as temp_dir:
            xml_file = Path(temp_dir) / "scan.xml"

            command = [
                self.nmap_path,
                "-sT",
                "-oX",
                str(xml_file),
                target,
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
                    "command": command,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "data": None,
                }

            parsed_data = self.parser.parse_file(xml_file)

            return {
                "success": True,
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "data": parsed_data,
            }


if __name__ == "__main__":
    scanner = NmapScanner()

    target = input("Enter authorized target: ").strip()

    result = scanner.scan(target)

    if not result["success"]:
        print("\n===== NMAP SCAN FAILED =====")
        print(result["stderr"])
        print(f"Nmap return code: {result['returncode']}")
        raise SystemExit(1)

    print("\n===== NMAP SCAN SUCCESSFUL =====")

    data = result["data"]

    print("Nmap version:", data["nmap_version"])
    print("Hosts found:", len(data["hosts"]))

    for host in data["hosts"]:
        print("\nHost status:", host["status"])
        print("Addresses:", host["addresses"])
        print("Hostnames:", host["hostnames"])

        print("Ports:")

        for port in host["ports"]:
            print(
                f"  {port['port']}/{port['protocol']} "
                f"{port['state']} "
                f"{port['service']}"
            )
