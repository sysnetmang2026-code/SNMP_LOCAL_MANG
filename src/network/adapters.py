"""Deteccion de informacion IPv4 para el adaptador de red local.

Las funciones de este modulo buscan un adaptador cuyo nombre contenga una pista
configurable, por defecto `wi-fi 6`, y devuelven los datos necesarios para
calcular el rango de escaneo Nmap. El resultado depende de la lista de
adaptadores disponible al importar el modulo.
"""

import ifaddr
import ipaddress


adapters = ifaddr.get_adapters()


def _iter_ipv4_adapters(adapter_name_hint="wi-fi 6"):
    """Itera las direcciones IPv4 de adaptadores cuyo nombre coincide."""

    for adapter in adapters:
        if adapter_name_hint.lower() in adapter.nice_name.lower():
            for ip in adapter.ips:
                if ip.is_IPv4:
                    yield ip


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
