import subprocess


class NmapScanner:
    """Basic wrapper around the Nmap command-line scanner."""

    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path

    def scan(self, target):
        """Run a basic Nmap scan against an authorized target."""

        command = [
            self.nmap_path,
            "-sT",
            target,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        return {
            "command": command,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }


if __name__ == "__main__":
    scanner = NmapScanner()

    target = input("Enter authorized target: ").strip()

    result = scanner.scan(target)

    print("\n===== NMAP OUTPUT =====")
    print(result["stdout"])

    if result["stderr"]:
        print("\n===== NMAP ERRORS =====")
        print(result["stderr"])

    print(f"\nNmap return code: {result['returncode']}")
