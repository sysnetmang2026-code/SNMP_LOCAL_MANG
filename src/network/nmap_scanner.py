"""Escaneo de red local con Nmap y persistencia en SQLite.

El modulo detecta dispositivos activos dentro de un rango IPv4, intenta resolver
su hostname por varias estrategias y consulta el fabricante a partir del prefijo
OUI de la direccion MAC. Los resultados se almacenan en la base `red.db` para
que la consola y el panel web puedan consultar un historico aun cuando el router
no responda.
"""

import json
import ipaddress
import socket
import sqlite3
from urllib.parse import urlparse

import nmap

from config import DATABASE_PATH, OUI_JSON_PATH, ROUTER_HOST, ROUTER_URL
from validators import normalize_mac


RUTA_JSON = str(OUI_JSON_PATH)
RUTA_DB = str(DATABASE_PATH)
def _router_ips():
    """Calcula IPs protegidas del router y su interfaz KAON secundaria."""

    values = {
        value
        for value in (
            str(ROUTER_HOST or "").strip(),
            str(urlparse(ROUTER_URL).hostname or "").strip(),
        )
        if value
    }
    protected = set(values)

    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue

        if address.version != 4:
            continue

        prefix = ".".join(value.split(".")[:3])
        protected.add(f"{prefix}.1")
        protected.add(f"{prefix}.2")

    return protected


ROUTER_IPS = _router_ips()


def is_router_device(ip="", hostname="", fabricante=""):
    """Identifica el router configurado para excluirlo de usuarios administrables."""

    ip = str(ip or "").strip()

    if ip in ROUTER_IPS:
        return True

    name = str(hostname or "").strip().lower()
    vendor = str(fabricante or "").strip().lower()
    router_name = any(word in name for word in ("router", "gateway", "puerta-de-enlace"))
    router_vendor = any(word in vendor for word in ("kaon", "arris", "technicolor", "sagemcom"))
    router_like_ip = ip.endswith(".1") or ip.endswith(".2")
    return router_vendor and (router_name or router_like_ip)


class EscanerRedDB:
    """Escaner Nmap con almacenamiento local de dispositivos detectados."""

    def __init__(self, db_name):
        """Inicializa la conexion SQLite, la tabla de destino y el catalogo OUI.

        Args:
            db_name: Ruta del archivo SQLite donde se guardaran los dispositivos.
        """

        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.create_table()

        try:
            self.cursor.execute("""
                ALTER TABLE dispositivos
                ADD COLUMN hostname TEXT
            """)
            self.conn.commit()
        except sqlite3.OperationalError:
            pass

        with open(RUTA_JSON, "r", encoding="utf-8") as archivo:
            self.oui_data = json.load(archivo)

    def create_table(self):
        """Crea la tabla `dispositivos` si no existe."""

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS dispositivos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                mac TEXT UNIQUE,
                fabricante TEXT,
                hostname TEXT
            )
        ''')
        self.conn.commit()

    def buscar_fabricante(self, mac):
        """Busca el fabricante asociado al prefijo OUI de una MAC."""

        prefijo = mac.upper()[0:8]
        return self.oui_data.get(prefijo, "Desconocido")

    def guardar_dispositivo(self, ip, mac, hostname, fabricante):
        """Inserta o actualiza un usuario detectado, excluyendo el router."""

        mac = normalize_mac(mac)

        if is_router_device(ip, hostname, fabricante):
            return False

        self.cursor.execute('''
            INSERT INTO dispositivos
            (ip, mac, hostname, fabricante)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = excluded.hostname,
                fabricante = excluded.fabricante
        ''', (
            ip,
            mac,
            hostname,
            fabricante,
        ))
        self.conn.commit()
        return True

    def mostrar_dispositivos(self):
        """Imprime en consola los dispositivos almacenados en la base local."""

        self.cursor.execute('''
            SELECT id, ip, mac,
                   hostname, fabricante
            FROM dispositivos
        ''')

        registros = self.cursor.fetchall()

        print("\n")
        print("=" * 110)
        print(
            f"| {'Nro.':<4}"
            f"| {'IP':<18}"
            f"| {'MAC':<20}"
            f"| {'HOSTNAME':<15}"
            f"| {'FABRICANTE':<35}|"
        )
        print("=" * 110)

        for fila in registros:
            print(
                f"| {fila[0]:<4}"
                f"| {fila[1]:<18}"
                f"| {fila[2]:<20}"
                f"| {fila[3]:<15}"
                f"| {fila[4]:<35}|"
            )

        print("=" * 110)

    def escanear_red(self, rango_red):
        """Escanea un rango IPv4 y persiste cada host con direccion MAC.

        Args:
            rango_red: Rango en notacion CIDR, por ejemplo `192.168.1.0/24`.
        """

        scanner = nmap.PortScanner()

        print(f"\nEscaneando red: {rango_red}...\n")

        try:
            scanner.scan(
                hosts=rango_red,
                arguments='-sn -PR -n',
            )
        except nmap.nmap.PortScannerError as e:
            print(f"Error Nmap: {e}")
            return []

        discovered = []

        for host in scanner.all_hosts():
            if 'mac' not in scanner[host]['addresses']:
                continue

            ip = host

            if is_router_device(ip):
                continue

            mac = normalize_mac(scanner[host]['addresses']['mac'])
            fabricante = self.buscar_fabricante(mac)
            hostname = "Desconocido"

            try:
                nombre_nmap = scanner[host].hostname()

                if nombre_nmap:
                    hostname = nombre_nmap
            except Exception:
                pass

            if hostname == "Desconocido":
                try:
                    hostname_dns = socket.gethostbyaddr(ip)[0]

                    if hostname_dns:
                        hostname = hostname_dns
                except Exception:
                    pass

            if hostname == "Desconocido":
                try:
                    hostscript = scanner[host].get('hostscript', [])

                    for script in hostscript:
                        salida = script.get('output', '')

                        if salida:
                            hostname = salida.split('\n')[0][:50]
                            break
                except Exception:
                    pass

            if is_router_device(ip, hostname, fabricante):
                continue

            saved = self.guardar_dispositivo(
                ip,
                mac,
                hostname,
                fabricante,
            )

            if not saved:
                continue

            discovered.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "fabricante": fabricante,
            })

            print(
                f"[+] {ip} | "
                f"{mac} | "
                f"{hostname} | "
                f"{fabricante}"
            )

        return discovered

    def close(self):
        """Cierra la conexion SQLite asociada al escaner."""

        self.conn.close()


if __name__ == "__main__":
    db = EscanerRedDB(RUTA_DB)

    red = input(
        "Introduce el rango de red "
        "(ejemplo 192.168.1.0/24): "
    )

    db.escanear_red(red)
    db.mostrar_dispositivos()
    db.close()
