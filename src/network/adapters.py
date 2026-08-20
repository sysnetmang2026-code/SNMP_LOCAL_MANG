"""Deteccion de informacion IPv4 para el adaptador de red local.

Las funciones de este modulo buscan adaptadores IPv4 activos y devuelven los
datos necesarios para ubicar la red del usuario. Cuando se entrega una pista de
nombre se prioriza ese adaptador, pero tambien existe un respaldo generico para
evitar depender de un nombre especifico como `wi-fi 6`.
"""

import ipaddress
import platform
import subprocess

import ifaddr


adapters = ifaddr.get_adapters()
PRIVATE_IPV4_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_usable_private_ipv4(value):
    """Indica si una IP parece pertenecer a una LAN administrable."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return (
        address.version == 4
        and not address.is_loopback
        and any(address in network for network in PRIVATE_IPV4_RANGES)
    )


def _iter_ipv4_adapters(adapter_name_hint="wi-fi 6", fallback=True):
    """Itera direcciones IPv4 priorizando el adaptador sugerido."""

    hinted = []
    generic = []

    for adapter in adapters:
        target = hinted if adapter_name_hint.lower() in adapter.nice_name.lower() else generic

        if adapter_name_hint.lower() in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4 and _is_usable_private_ipv4(ip.ip):
                    target.append(ip)
        elif fallback:
            for ip in adapter.ips:
                if ip.is_IPv4 and _is_usable_private_ipv4(ip.ip):
                    target.append(ip)

    yield from hinted
    yield from generic


def get_localhost_ip(adapter_name_hint="wi-fi 6"):
    """Devuelve la primera direccion IPv4 encontrada para el adaptador."""

    for ip in _iter_ipv4_adapters(adapter_name_hint):
        return ip.ip


def get_subnet_mask(adapter_name_hint="wi-fi 6"):
    """Devuelve el prefijo CIDR de la primera direccion IPv4 encontrada."""

    for ip in _iter_ipv4_adapters(adapter_name_hint):
        return ip.network_prefix


def get_network_address(adapter_name_hint="wi-fi 6"):
    """Calcula la direccion de red IPv4 del adaptador seleccionado."""

    for ip in _iter_ipv4_adapters(adapter_name_hint):
        iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")
        return iface.network.network_address


def get_broadcast(adapter_name_hint="wi-fi 6"):
    """Calcula la direccion broadcast IPv4 del adaptador seleccionado."""

    for ip in _iter_ipv4_adapters(adapter_name_hint):
        iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")
        return iface.network.broadcast_address


def get_subnet(adapter_name_hint="wi-fi 6"):
    """Devuelve la subred IPv4 completa en notacion CIDR."""

    for ip in _iter_ipv4_adapters(adapter_name_hint):
        iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")
        return iface.network


def _run_gateway_command(command):
    """Ejecuta un comando del sistema y devuelve su salida en texto."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    if result.returncode != 0:
        return ""

    return result.stdout


def _windows_default_gateway():
    """Obtiene la puerta de enlace IPv4 desde la tabla de rutas de Windows."""

    output = _run_gateway_command(["route", "print", "-4", "0.0.0.0"])

    for raw_line in output.splitlines():
        parts = raw_line.split()

        if len(parts) < 5 or parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue

        gateway = parts[2]

        if _is_usable_private_ipv4(gateway):
            return gateway

    return None


def _unix_default_gateway():
    """Obtiene la puerta de enlace IPv4 en Linux o macOS."""

    output = _run_gateway_command(["ip", "route", "show", "default"])

    for raw_line in output.splitlines():
        parts = raw_line.split()

        if parts[:1] == ["default"] and "via" in parts:
            gateway = parts[parts.index("via") + 1]

            if _is_usable_private_ipv4(gateway):
                return gateway

    output = _run_gateway_command(["route", "-n", "get", "default"])

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip()

            if _is_usable_private_ipv4(gateway):
                return gateway

    return None


def get_default_gateway():
    """Devuelve la puerta de enlace IPv4 local, normalmente la IP del router."""

    if platform.system().lower() == "windows":
        return _windows_default_gateway()

    return _unix_default_gateway()
