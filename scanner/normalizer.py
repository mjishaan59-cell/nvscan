class ResultNormalizer:
    """Convert scanner results into a common normalized format."""

    def normalize_nmap(self, scan_data):
        """Normalize Nmap host and port results."""

        normalized = []

        for host in scan_data.get("hosts", []):
            addresses = [
                item["address"]
                for item in host.get("addresses", [])
            ]

            hostnames = [
                item["name"]
                for item in host.get("hostnames", [])
            ]

            for port in host.get("ports", []):
                normalized.append(
                    {
                        "source": "nmap",
                        "type": "service",
                        "host": addresses[0] if addresses else None,
                        "hostname": (
                            hostnames[0]
                            if hostnames
                            else None
                        ),
                        "port": port.get("port"),
                        "protocol": port.get("protocol"),
                        "state": port.get("state"),
                        "service": port.get("service"),
                        "product": port.get("product"),
                        "version": port.get("version"),
                        "evidence": None,
                    }
                )

        return normalized

    def normalize_http(self, http_result):
        """Normalize HTTP scanner results."""

        if not http_result.get("success"):
            return []

        return [
            {
                "source": "http_scanner",
                "type": "http_service",
                "host": http_result.get("url"),
                "hostname": None,
                "port": None,
                "protocol": None,
                "state": "accessible",
                "service": "http",
                "product": None,
                "version": None,
                "evidence": {
                    "status_code": http_result.get(
                        "status_code"
                    ),
                    "content_length": http_result.get(
                        "content_length"
                    ),
                    "headers": http_result.get(
                        "headers",
                        {},
                    ),
                },
            }
        ]

    def normalize_directories(self, directory_result):
        """Normalize directory enumeration results."""

        if not directory_result.get("success"):
            return []

        normalized = []

        for item in directory_result.get("results", []):
            normalized.append(
                {
                    "source": "directory_enum",
                    "type": "web_path",
                    "host": directory_result.get(
                        "base_url"
                    ),
                    "hostname": None,
                    "port": None,
                    "protocol": "http",
                    "state": (
                        "accessible"
                        if item.get("status_code") in range(
                            200,
                            400,
                        )
                        else "not_accessible"
                    ),
                    "service": "http",
                    "product": None,
                    "version": None,
                    "evidence": {
                        "path": item.get("path"),
                        "url": item.get("url"),
                        "status_code": item.get(
                            "status_code"
                        ),
                        "content_length": item.get(
                            "content_length"
                        ),
                        "redirected": item.get(
                            "redirected"
                        ),
                        "error": item.get("error"),
                    },
                }
            )

        return normalized


if __name__ == "__main__":
    normalizer = ResultNormalizer()

    sample_nmap = {
        "hosts": [
            {
                "addresses": [
                    {
                        "address": "127.0.0.1",
                        "type": "ipv4",
                    }
                ],
                "hostnames": [
                    {
                        "name": "localhost",
                        "type": "PTR",
                    }
                ],
                "ports": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "product": "Apache httpd",
                        "version": "2.4.63",
                    }
                ],
            }
        ]
    }

    normalized = normalizer.normalize_nmap(
        sample_nmap
    )

    print("===== NORMALIZED RESULT =====")

    for item in normalized:
        print(item)
