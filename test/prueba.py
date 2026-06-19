"""
prueba.py - Logica principal SNMP
==================================
Tarea 1: Identificar y guardar valores via pysnmp
Tarea 2: Manejo de ficheros (OIDS/oids.txt)
Tarea 4: Actualizacion automatica cada N segundos
"""

import sys
import asyncio
import os
import threading
import time
from datetime import datetime
from pysnmp.hlapi.v1arch.asyncio import (
    SnmpDispatcher, CommunityData, UdpTransportTarget, get_cmd
)

sys.stdout.reconfigure(encoding='utf-8')

# -------------------------------------------
# CONFIGURACION
# -------------------------------------------
AGENTE_IP = "192.168.56.2"
PUERTO    = 161
COMUNIDAD = "public"
ARCHIVO   = "OIDS/oids.txt"
INTERVALO = 10  # segundos entre actualizaciones

# -------------------------------------------
# TAREA 1 - OIDs identificados del MikroTik
# -------------------------------------------
OIDS = {
    "Descripcion del sistema" : "1.3.6.1.2.1.1.1.0",       # sysDescr
    "Nombre del router"       : "1.3.6.1.2.1.1.5.0",       # sysName
    "Uptime"                  : "1.3.6.1.2.1.1.3.0",       # sysUpTime (en centisegundos)
    "Numero de interfaces"    : "1.3.6.1.2.1.2.1.0",       # ifNumber
    "RX ether1 (bytes)"       : "1.3.6.1.2.1.2.2.1.10.3",  # ifInOctets
    "TX ether1 (bytes)"       : "1.3.6.1.2.1.2.2.1.16.3",  # ifOutOctets
}

# Flags del auto-update
_auto_update_activo = False
_hilo_update        = None

# Guarda la lectura anterior para calcular velocidad real
_lectura_anterior = {"rx": 0, "tx": 0, "tiempo": 0}


# -------------------------------------------
# CONVERSIONES
# -------------------------------------------
def convertir_uptime(centisegundos):
    """
    El uptime SNMP viene en centisegundos.
    Lo convierte a formato: X dias, HH:MM:SS
    """
    try:
        segundos_total = int(centisegundos) // 100
        dias           = segundos_total // 86400
        horas          = (segundos_total % 86400) // 3600
        minutos        = (segundos_total % 3600) // 60
        segundos       = segundos_total % 60
        return f"{dias}d {horas:02}:{minutos:02}:{segundos:02}"
    except (ValueError, TypeError):
        return centisegundos


def convertir_bytes_a_mb(bytes_valor):
    """Convierte bytes a Megabytes con 4 decimales."""
    try:
        mb = int(bytes_valor) / (1024 * 1024)
        return f"{mb:.4f} MB"
    except (ValueError, TypeError):
        return bytes_valor


def calcular_velocidad(bytes_actual, bytes_anterior, segundos):
    """
    Calcula la velocidad real en MB/s entre dos lecturas.
    velocidad = (bytes_actual - bytes_anterior) / segundos / 1024 / 1024
    """
    try:
        diff = int(bytes_actual) - int(bytes_anterior)
        if diff < 0:
            diff = 0  # contador reiniciado
        mb_por_seg = diff / max(segundos, 1) / (1024 * 1024)
        return f"{mb_por_seg:.4f} MB/s"
    except (ValueError, TypeError):
        return "0.0000 MB/s"


def aplicar_conversiones(resultados: dict):
    """
    Aplica conversiones y calcula velocidad real
    comparando con la lectura anterior.
    """
    global _lectura_anterior
    import time

    convertidos = resultados.copy()

    if "Uptime" in convertidos:
        convertidos["Uptime"] = convertir_uptime(convertidos["Uptime"])

    # Calcular velocidad real entre lecturas
    rx_actual = int(resultados.get("RX ether1 (bytes)", 0) or 0)
    tx_actual = int(resultados.get("TX ether1 (bytes)", 0) or 0)
    tiempo_actual = time.time()

    segundos_transcurridos = tiempo_actual - _lectura_anterior["tiempo"]

    if _lectura_anterior["tiempo"] > 0 and segundos_transcurridos > 0:
        convertidos["RX ether1 (MB)"] = calcular_velocidad(
            rx_actual, _lectura_anterior["rx"], segundos_transcurridos
        )
        convertidos["TX ether1 (MB)"] = calcular_velocidad(
            tx_actual, _lectura_anterior["tx"], segundos_transcurridos
        )
    else:
        # Primera lectura: mostrar acumulado convertido
        convertidos["RX ether1 (MB)"] = convertir_bytes_a_mb(rx_actual)
        convertidos["TX ether1 (MB)"] = convertir_bytes_a_mb(tx_actual)

    # Guardar lectura actual como anterior para la proxima vez
    _lectura_anterior["rx"]     = rx_actual
    _lectura_anterior["tx"]     = tx_actual
    _lectura_anterior["tiempo"] = tiempo_actual

    # Eliminar claves de bytes crudos
    convertidos.pop("RX ether1 (bytes)", None)
    convertidos.pop("TX ether1 (bytes)", None)

    return convertidos


# -------------------------------------------
# TAREA 2 - Manejo de ficheros
# -------------------------------------------
def asegurar_directorio():
    os.makedirs("OIDS", exist_ok=True)


def cargar_datos(nombre_archivo=ARCHIVO):
    datos = {}
    try:
        with open(nombre_archivo, "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if "=" in linea:
                    clave, valor = linea.split("=", 1)
                    datos[clave.strip()] = valor.strip()
    except FileNotFoundError:
        pass
    return datos


def guardar_todos(resultados: dict, nombre_archivo=ARCHIVO):
    asegurar_directorio()
    datos_existentes = cargar_datos(nombre_archivo)
    datos_existentes.update(resultados)
    datos_existentes["ultima_actualizacion"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(nombre_archivo, "w", encoding="utf-8") as f:
        for k, v in datos_existentes.items():
            f.write(f"{k}={v}\n")


# -------------------------------------------
# TAREA 1 - Consultas SNMP con pysnmp
# Incluye manejo de errores si el router
# no responde o esta apagado
# -------------------------------------------
async def consultar_oid(oid: str):
    try:
        with SnmpDispatcher() as dispatcher:
            resultado = await get_cmd(
                dispatcher,
                CommunityData(COMUNIDAD, mpModel=1),
                await UdpTransportTarget.create((AGENTE_IP, PUERTO), timeout=3, retries=1),
                (oid, None)
            )

        errorIndication, errorStatus, errorIndex, varBinds = resultado

        if errorIndication:
            # El router no responde (apagado, sin red, timeout)
            print(f"  Sin respuesta del router ({oid}): {errorIndication}")
            return None
        elif errorStatus:
            # El router responde pero reporta un error SNMP
            print(f"  Error SNMP en {oid}: {errorStatus.prettyPrint()}")
            return None
        else:
            for varBind in varBinds:
                return varBind[1].prettyPrint()

    except Exception as e:
        # Cualquier otro error inesperado de red o libreria
        print(f"  Error inesperado en {oid}: {e}")
        return None

    return None


async def consultar_todos():
    """
    Consulta todos los OIDs y aplica conversiones.
    Retorna dict vacio si el router no responde.
    """
    resultados = {}
    for nombre, oid in OIDS.items():
        valor = await consultar_oid(oid)
        if valor is not None:
            resultados[nombre] = valor

    if not resultados:
        return {}  # Router sin respuesta, se maneja en Menu.py

    return aplicar_conversiones(resultados)


# -------------------------------------------
# TAREA 4 - Actualizacion automatica
# -------------------------------------------
def _loop_auto_update():
    global _auto_update_activo
    print(f"\n  Auto-update iniciado. Intervalo: {INTERVALO} segundos.")
    while _auto_update_activo:
        resultados = asyncio.run(consultar_todos())
        if resultados:
            guardar_todos(resultados)
            print(f"  Datos actualizados: {datetime.now().strftime('%H:%M:%S')}")
        else:
            # Manejo de error: router no responde durante auto-update
            print(f"  Sin respuesta del router a las {datetime.now().strftime('%H:%M:%S')}. Reintentando en {INTERVALO}s.")
        time.sleep(INTERVALO)
    print("  Auto-update detenido.")


def iniciar_auto_update():
    global _auto_update_activo, _hilo_update
    if _auto_update_activo:
        print("  El auto-update ya esta en ejecucion.")
        return
    _auto_update_activo = True
    _hilo_update = threading.Thread(target=_loop_auto_update, daemon=True)
    _hilo_update.start()


def detener_auto_update():
    global _auto_update_activo
    if not _auto_update_activo:
        print("  El auto-update no esta activo.")
        return
    _auto_update_activo = False