import os
import re
import paramiko
from dotenv import load_dotenv

load_dotenv()

ROUTER_HOST = os.getenv("ROUTER_HOST")
ROUTER_USER = os.getenv("ROUTER_USER")
ROUTER_PASS = os.getenv("ROUTER_PASS")
WIFI_IFACE = os.getenv("WIFI_IFACE", "@wifi-iface[0]")


def validar_mac(mac):
    patron = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    return re.match(patron, mac) is not None


def ejecutar_comando_ssh(comando):
    cliente = paramiko.SSHClient()
    cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        cliente.connect(
            hostname=ROUTER_HOST,
            username=ROUTER_USER,
            password=ROUTER_PASS,
            timeout=10
        )

        stdin, stdout, stderr = cliente.exec_command(comando)

        salida = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            return False, error

        return True, salida

    except Exception as e:
        return False, str(e)

    finally:
        cliente.close()


def bloquear_dispositivo(mac):
    if not validar_mac(mac):
        return False, "La dirección MAC no es válida."

    comandos = f"""
uci set wireless.{WIFI_IFACE}.macfilter='deny'
uci add_list wireless.{WIFI_IFACE}.maclist='{mac}'
uci commit wireless
wifi reload
"""

    return ejecutar_comando_ssh(comandos)


if __name__ == "__main__":
    mac_dispositivo = input("Ingrese la MAC del dispositivo a bloquear: ")

    correcto, respuesta = bloquear_dispositivo(mac_dispositivo)

    if correcto:
        print("Dispositivo bloqueado correctamente.")
    else:
        print("Error al bloquear dispositivo:")
        print(respuesta)