import subprocess
import tempfile
from pathlib import Path

from scanner.parser import NmapXMLParser
from scanner.target_validator import TargetValidator


class ServiceDetector:
    """Detect services and versions on an authorized target."""

    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.parser = NmapXMLParser()
        self.validator = TargetValidator()

    def detect(self, target):
        """Validate target, detect services, and return structured results."""

        valid, normalized_target, error = self.validator.validate(target)

        if not valid:
            return {
                "success": False,
                "error": error,
                "hosts": [],
            }

        with tempfile.TemporaryDirectory(prefix="nvscan-services-") as temp_dir:
            xml_file = Path(temp_dir) / "services.xml"

            command = [
                self.nmap_path,
                "-sT",
                "-sV",
                "-oX",
                str(xml_file),
                normalized_target,
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr.strip()
                    or "Nmap service detection failed.",
                    "hosts": [],
                }

            parsed_data = self.parser.parse_file(xml_file)

            return {
                "success": True,
                "error": None,
                "hosts": parsed_data["hosts"],
            }


if __name__ == "__main__":
    detector = ServiceDetector()

    target = input("Enter authorized target: ").strip()

    result = detector.detect(target)

    if not result["success"]:
        print("\n===== SERVICE DETECTION FAILED =====")
        print(f"Reason: {result['error']}")
        raise SystemExit(1)

    print("\n===== SERVICE DETECTION SUCCESSFUL =====")
    print(f"Hosts found: {len(result['hosts'])}")

    for host in result["hosts"]:
        print("\nHost status:", host["status"])
        print("Addresses:", host["addresses"])

        print("Services:")

        for port in host["ports"]:
            if port["state"] == "open":
                print(
                    f"  {port['port']}/{port['protocol']} "
                    f"{port['service']} "
                    f"{port['product'] or ''} "
                    f"{port['version'] or ''}"
                )
