import sqlite3
import socket
import nmap
import json

from config import DATABASE_PATH, OUI_JSON_PATH


RUTA_JSON = str(OUI_JSON_PATH)
RUTA_DB = str(DATABASE_PATH)


class EscanerRedDB:

    def __init__(self, db_name):

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

        # =========================
        # CARGAR JSON OUI
        # =========================

        with open(RUTA_JSON, "r", encoding="utf-8") as archivo:
        
            self.oui_data = json.load(archivo)

    # =========================
    # CREAR TABLA
    # =========================

    def create_table(self):

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

    # =========================
    # BUSCAR OUI
    # =========================

    def buscar_fabricante(self, mac):

        prefijo = mac.upper()[0:8]

        return self.oui_data.get(
            prefijo,
            "Desconocido"
        )

    # =========================
    # GUARDAR DISPOSITIVO
    # =========================

    def guardar_dispositivo(
        self,
        ip,
        mac,
        hostname,
        fabricante
    ):

        try:

            self.cursor.execute('''
                INSERT INTO dispositivos
                (ip, mac, hostname, fabricante)

                VALUES (?, ?, ?, ?)
            ''', (
                ip,
                mac,
                hostname,
                fabricante
            ))

            self.conn.commit()

        except sqlite3.IntegrityError:

            pass

    # =========================
    # MOSTRAR DISPOSITIVOS
    # =========================

    def mostrar_dispositivos(self):

        self.cursor.execute('''
            SELECT id, ip, mac,
                   hostname, fabricante
            FROM dispositivos
        ''')

        registros = self.cursor.fetchall()

        print("\n")

        print("=" * 110)

        print(
            f"| {'N°':<4}"
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

    # =========================
    # ESCANEAR RED
    # =========================

    def escanear_red(self, rango_red):


        scanner = nmap.PortScanner()

        print(f"\nEscaneando red: {rango_red}...\n")

        try:

            scanner.scan(
                hosts=rango_red,
                arguments='-sn -PR -n'
            )

        except nmap.nmap.PortScannerError as e:

            print(f"Error Nmap: {e}")

            return

        for host in scanner.all_hosts():

            if 'mac' in scanner[host]['addresses']:

                ip = host

                mac = scanner[host]['addresses']['mac']

                # =========================
                # FABRICANTE
                # =========================

                fabricante = self.buscar_fabricante(mac)

                # =========================
                # HOSTNAME
                # =========================

                hostname = "Desconocido"

                # Método 1: hostname directo Nmap
                try:

                    nombre_nmap = scanner[host].hostname()

                    if nombre_nmap:

                        hostname = nombre_nmap

                except:

                    pass

                # Método 2: reverse DNS
                if hostname == "Desconocido":

                    try:

                        hostname_dns = socket.gethostbyaddr(ip)[0]

                        if hostname_dns:

                            hostname = hostname_dns

                    except:

                        pass

                # Método 3: scripts NSE
                if hostname == "Desconocido":

                    try:

                        hostscript = scanner[host].get('hostscript', [])

                        for script in hostscript:

                            salida = script.get('output', '')

                            if salida:

                                hostname = salida.split('\n')[0][:50]
                                break

                    except:

                        pass

                self.guardar_dispositivo(
                    ip,
                    mac,
                    hostname,
                    fabricante
                )

                print(
                    f"[+] {ip} | "
                    f"{mac} | "
                    f"{hostname} | "
                    f"{fabricante}"
                )
    # =========================
    # CERRAR CONEXIÓN
    # =========================

    def close(self):

        self.conn.close()


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    db = EscanerRedDB(RUTA_DB)

    red = input(
        "Introduce el rango de red "
        "(ejemplo 192.168.1.0/24): "
    )

    db.escanear_red(red)

    db.mostrar_dispositivos()

    db.close()
