"""Pruebas de consulta SNMP contra un agente Mikrotik.

El modulo usa `pysnmp` en modo asincrono para leer OIDs definidos en una lista
interna o cargados desde `test/OIDS/oids.txt`. Cada consulta puede persistir el
ultimo valor obtenido para conservar una referencia simple de monitoreo.
"""

import asyncio

from pysnmp.hlapi.v1arch.asyncio import *


AGENTE_IP = "192.168.56.2"
PUERTO = 161
COMUNIDAD = "public"

# OIDs base usados para pruebas con RouterOS/Mikrotik.
OIDS = [
    "1.3.6.1.2.1.1.1.0",  # sysDescr
    "1.3.6.1.2.1.1.5.0",  # system name
    "1.3.6.1.2.1.1.3.0",  # uptime
    "1.3.6.1.2.1.2.1.0",  # number of interfaces
    "1.3.6.1.2.1.2.2.1.10.3",  # RX ether1
    "1.3.6.1.2.1.2.2.1.16.3",  # TX ether1
]


async def monitorear():
    """Consulta continuamente la lista fija de OIDs con pausas entre ciclos."""

    while True:
        for oid in OIDS:
            await consultar_oid(oid)
            await asyncio.sleep(5)

        print("Actualizando en 5 segundos...")
        print("--------------------------------")
        await asyncio.sleep(5)


def cargar_oids(nombre_archivo="OIDS/oids.txt"):
    """Carga pares `oid=valor` desde un archivo de texto simple."""

    oids = {}

    try:
        with open(nombre_archivo, "r") as archivo:
            for linea in archivo:
                linea = linea.strip()

                if "=" in linea:
                    clave, valor = linea.split("=", 1)
                    oids[clave.strip()] = valor.strip()
    except FileNotFoundError:
        print("Archivo no encontrado, se creara automaticamente.")

    return oids


def guardar_oid(clave, valor, nombre_archivo="OIDS/oids.txt"):
    """Actualiza o agrega el ultimo valor conocido para un OID."""

    oids = cargar_oids(nombre_archivo)
    oids[clave] = valor

    with open(nombre_archivo, "w") as archivo:
        for k, v in oids.items():
            archivo.write(f"{k}={v}\n")


async def consultar_oid(oid):
    """Consulta un OID especifico por SNMP v1 y guarda su valor."""

    with SnmpDispatcher() as snmpDispatcher:
        iterator = await get_cmd(
            snmpDispatcher,
            CommunityData(COMUNIDAD, mpModel=0),
            await UdpTransportTarget.create((AGENTE_IP, PUERTO)),
            (oid, None),
        )

        errorIndication, errorStatus, errorIndex, varBinds = iterator

        if errorIndication:
            print(f"Error en {oid}: {errorIndication}")

        elif errorStatus:
            print(
                f"SNMP Error en {oid}: {errorStatus.prettyPrint()}"
            )
        else:
            for varBind in varBinds:
                nombre = varBind[0].prettyPrint()
                valor = varBind[1].prettyPrint()

                print(f"{oid} = {valor}")
                guardar_oid(oid, valor, "OIDS/oids.txt")
