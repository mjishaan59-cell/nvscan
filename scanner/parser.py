import xml.etree.ElementTree as ET


class NmapXMLParser:
    """Parse Nmap XML output into structured Python data."""

    def parse_file(self, xml_file):
        tree = ET.parse(xml_file)
        root = tree.getroot()

        result = {
            "scanner": root.get("scanner"),
            "nmap_version": root.get("version"),
            "hosts": [],
        }

        for host in root.findall("host"):
            host_data = {
                "status": None,
                "addresses": [],
                "hostnames": [],
                "ports": [],
            }

            # Host status
            status = host.find("status")
            if status is not None:
                host_data["status"] = status.get("state")

            # IP/MAC/other addresses
            for address in host.findall("address"):
                host_data["addresses"].append({
                    "address": address.get("addr"),
                    "type": address.get("addrtype"),
                })

            # Hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    host_data["hostnames"].append({
                        "name": hostname.get("name"),
                        "type": hostname.get("type"),
                    })

            # Ports
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "state": None,
                        "service": None,
                        "product": None,
                        "version": None,
                    }

                    state = port.find("state")
                    if state is not None:
                        port_data["state"] = state.get("state")

                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name")
                        port_data["product"] = service.get("product")
                        port_data["version"] = service.get("version")

                    host_data["ports"].append(port_data)

            result["hosts"].append(host_data)

        return result
