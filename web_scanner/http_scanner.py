import urllib.error
import urllib.request

from scanner.target_validator import TargetValidator


class HTTPScanner:
    """Collect basic information from an HTTP/HTTPS service."""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.validator = TargetValidator()

    def scan(self, target):
        """Connect to an authorized HTTP/HTTPS target."""

        valid, normalized_target, error = self.validator.validate(target)

        if not valid:
            return {
                "success": False,
                "error": error,
                "url": None,
                "status_code": None,
                "headers": {},
                "content_length": None,
            }

        # If the user gives only a hostname/IP, use HTTP by default.
        if not normalized_target.startswith(("http://", "https://")):
            url = f"http://{normalized_target}"
        else:
            url = normalized_target

        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "nvscan/1.0"
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
            ) as response:

                headers = dict(response.headers)

                content_length = headers.get("Content-Length")

                if content_length is not None:
                    try:
                        content_length = int(content_length)
                    except ValueError:
                        content_length = None

                return {
                    "success": True,
                    "error": None,
                    "url": response.geturl(),
                    "status_code": response.status,
                    "headers": headers,
                    "content_length": content_length,
                }

        except urllib.error.HTTPError as error:
            return {
                "success": True,
                "error": None,
                "url": error.geturl(),
                "status_code": error.code,
                "headers": dict(error.headers),
                "content_length": None,
            }

        except urllib.error.URLError as error:
            return {
                "success": False,
                "error": str(error.reason),
                "url": url,
                "status_code": None,
                "headers": {},
                "content_length": None,
            }

        except TimeoutError:
            return {
                "success": False,
                "error": "HTTP request timed out.",
                "url": url,
                "status_code": None,
                "headers": {},
                "content_length": None,
            }

        except Exception as error:
            return {
                "success": False,
                "error": str(error),
                "url": url,
                "status_code": None,
                "headers": {},
                "content_length": None,
            }


if __name__ == "__main__":
    scanner = HTTPScanner()

    target = input("Enter authorized HTTP target: ").strip()

    result = scanner.scan(target)

    if not result["success"]:
        print("\n===== HTTP SCAN FAILED =====")
        print(f"Reason: {result['error']}")
        raise SystemExit(1)

    print("\n===== HTTP SCAN SUCCESSFUL =====")
    print("URL:", result["url"])
    print("Status code:", result["status_code"])
    print("Content length:", result["content_length"])

    print("\nHeaders:")

    for name, value in result["headers"].items():
        print(f"  {name}: {value}")
