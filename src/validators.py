import re


MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def normalize_mac(mac):
    return mac.strip().upper()


def is_valid_mac(mac):
    return MAC_PATTERN.match(normalize_mac(mac)) is not None

