import urllib.error
import urllib.request

from scanner.target_validator import TargetValidator


class DirectoryEnumerator:
    """Enumerate common web paths on an authorized HTTP target."""

    DEFAULT_PATHS = [
        "/",
        "/admin",
        "/login",
        "/robots.txt",
        "/uploads",
        "/backup",
        "/api",
    ]

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.validator = TargetValidator()

    def enumerate(self, target, paths=None):
        """Test a list of web paths against an authorized target."""

        valid, normalized_target, error = self.validator.validate(target)

        if not valid:
            return {
                "success": False,
                "error": error,
                "base_url": None,
                "results": [],
            }

        if paths is None:
            paths = self.DEFAULT_PATHS

        base_url = normalized_target

        if not base_url.startswith(("http://", "https://")):
            base_url = f"http://{base_url}"

        base_url = base_url.rstrip("/")

        results = []

        for path in paths:
            if not path.startswith("/"):
                path = f"/{path}"

            url = f"{base_url}{path}"

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

                    content_length = response.headers.get(
                        "Content-Length"
                    )

                    results.append(
                        {
                            "path": path,
                            "url": response.geturl(),
                            "status_code": response.status,
                            "content_length": content_length,
                            "redirected": response.geturl() != url,
                            "error": None,
                        }
                    )

            except urllib.error.HTTPError as error:
                results.append(
                    {
                        "path": path,
                        "url": error.geturl(),
                        "status_code": error.code,
                        "content_length": error.headers.get(
                            "Content-Length"
                        ),
                        "redirected": error.geturl() != url,
                        "error": None,
                    }
                )

            except urllib.error.URLError as error:
                results.append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": None,
                        "content_length": None,
                        "redirected": False,
                        "error": str(error.reason),
                    }
                )

            except TimeoutError:
                results.append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": None,
                        "content_length": None,
                        "redirected": False,
                        "error": "Request timed out.",
                    }
                )

            except Exception as error:
                results.append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": None,
                        "content_length": None,
                        "redirected": False,
                        "error": str(error),
                    }
                )

        return {
            "success": True,
            "error": None,
            "base_url": base_url,
            "results": results,
        }


if __name__ == "__main__":
    enumerator = DirectoryEnumerator()

    target = input("Enter authorized HTTP target: ").strip()

    result = enumerator.enumerate(target)

    if not result["success"]:
        print("\n===== DIRECTORY ENUMERATION FAILED =====")
        print(f"Reason: {result['error']}")
        raise SystemExit(1)

    print("\n===== DIRECTORY ENUMERATION SUCCESSFUL =====")
    print("Base URL:", result["base_url"])

    print("\nResults:")

    for item in result["results"]:
        status = item["status_code"]

        if status is None:
            print(
                f"  {item['path']} -> ERROR: {item['error']}"
            )
        else:
            print(
                f"  {item['path']} -> "
                f"{status} "
                f"(length={item['content_length']})"
            )
