"""Validadores compartidos para datos de red.

Actualmente el modulo concentra la normalizacion y validacion de direcciones MAC
en formato hexadecimal separado por dos puntos. Se mantiene separado para que la
consola, el panel web y los clientes de router apliquen exactamente la misma
regla de entrada.
"""

import re


MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def normalize_mac(mac):
    """Devuelve una MAC sin espacios laterales y en mayusculas."""

    return mac.strip().upper()


def is_valid_mac(mac):
    """Indica si `mac` cumple el formato `AA:BB:CC:DD:EE:FF`."""

    return MAC_PATTERN.match(normalize_mac(mac)) is not None

