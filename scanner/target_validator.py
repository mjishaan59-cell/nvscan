import ipaddress
import re


class TargetValidator:
    """Validate targets before they are passed to Nmap."""

    HOSTNAME_PATTERN = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.)*"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
    )

    def validate(self, target):
        """
        Validate an IPv4/IPv6 address, network, or hostname.

        Returns:
            tuple: (is_valid, normalized_target, error_message)
        """

        if not isinstance(target, str):
            return False, None, "Target must be a string."

        target = target.strip()

        if not target:
            return False, None, "Target cannot be empty."

        # Reject whitespace inside the target.
        if any(char.isspace() for char in target):
            return False, None, "Target cannot contain whitespace."

        # Check IP address.
        try:
            ip = ipaddress.ip_address(target)
            return True, str(ip), None
        except ValueError:
            pass

        # Check network/CIDR.
        try:
            network = ipaddress.ip_network(target, strict=False)
            return True, str(network), None
        except ValueError:
            pass

        # Reject values that look like IPv4 addresses
        # but contain invalid octets.
        if target.count(".") == 3 and all(
            part.isdigit() for part in target.split(".")
        ):
            return False, None, "Invalid IPv4 address."

        # Check hostname syntax.
        if self.HOSTNAME_PATTERN.fullmatch(target):
            return True, target.lower(), None

        return False, None, "Invalid IP address, network, or hostname."


if __name__ == "__main__":
    validator = TargetValidator()

    while True:
        target = input("Enter target (or 'quit'): ").strip()

        if target.lower() == "quit":
            break

        valid, normalized, error = validator.validate(target)

        if valid:
            print(f"VALID: {normalized}")
        else:
            print(f"INVALID: {error}")
