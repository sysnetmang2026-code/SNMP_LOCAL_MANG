"""Validadores compartidos para datos de red.

Actualmente el modulo concentra la normalizacion y validacion de direcciones MAC
en formato hexadecimal separado por dos puntos y palabras clave URL usadas por
el control parental del router. Se mantiene separado para que la consola, el
panel web y los clientes de router apliquen exactamente la misma regla de
entrada.
"""

import re
from urllib.parse import urlparse


MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
URL_KEYWORD_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,253}[A-Za-z0-9]$")


def normalize_mac(mac):
    """Devuelve una MAC canonica `AA:BB:CC:DD:EE:FF` cuando es posible."""

    value = str(mac or "").strip().upper().replace("-", ":")
    compact = re.sub(r"[^0-9A-F]", "", value)

    if len(compact) == 12:
        return ":".join(compact[index:index + 2] for index in range(0, 12, 2))

    return value


def is_valid_mac(mac):
    """Indica si `mac` cumple el formato `AA:BB:CC:DD:EE:FF`."""

    return MAC_PATTERN.match(normalize_mac(mac)) is not None


def normalize_url_keyword(value):
    """Normaliza una URL o dominio al valor que espera `FilteringUrlKeyword`."""

    value = value.strip().lower()

    if not value:
        return ""

    parsed = urlparse(value if "://" in value else f"//{value}")
    keyword = parsed.netloc or parsed.path
    keyword = keyword.split("@")[-1].split(":")[0].strip(".")

    if keyword.startswith("*."):
        keyword = keyword[2:]

    return keyword


def is_valid_url_keyword(value):
    """Indica si el dominio/palabra clave es aceptable para el router KAON."""

    keyword = normalize_url_keyword(value)
    return (
        bool(keyword)
        and len(keyword) <= 255
        and ".." not in keyword
        and URL_KEYWORD_PATTERN.match(keyword) is not None
    )

