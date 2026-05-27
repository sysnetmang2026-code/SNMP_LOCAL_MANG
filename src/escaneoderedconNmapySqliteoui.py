import sqlite3
import nmap
import data


class EscanerRedDB:

    def __init__(self, db_name):

        self.db_name = db_name

        self.conn = sqlite3.connect(self.db_name)

        self.cursor = self.conn.cursor()

        self.create_table()
        try:

            self.cursor.execute("""
                ALTER TABLE dispositivos
                ADD COLUMN marca_oui TEXT
            """)

            self.conn.commit()

        except sqlite3.OperationalError:

            pass
        # Cargar archivo JSON OUI
        with open("oui.json", "r", encoding="utf-8") as archivo:

            self.oui_data = json.load(archivo)

    # Crear tabla
    def create_table(self):

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS dispositivos (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                mac TEXT UNIQUE,
                marca_oui TEXT,
                fabricante TEXT
            )
        ''')

        self.conn.commit()

    # Buscar marca OUI
    def buscar_oui(self, mac):

        prefijo = mac.upper()[0:8]

        return self.oui_data.get(prefijo, "Desconocido")

    # Guardar dispositivo
    def guardar_dispositivo(self, ip, mac, marca_oui, fabricante):

        try:

            self.cursor.execute('''
                INSERT INTO dispositivos
                (ip, mac, marca_oui, fabricante)

                VALUES (?, ?, ?, ?)
            ''', (ip, mac, marca_oui, fabricante))

            self.conn.commit()

        except sqlite3.IntegrityError:

            pass

    # Mostrar dispositivos
    def mostrar_dispositivos(self):

        self.cursor.execute('''
            SELECT id, ip, mac, marca_oui, fabricante
            FROM dispositivos
        ''')

        registros = self.cursor.fetchall()

        print("\n")

        print("=" * 110)

        print(
            f"| {'N°':<4}"
            f"| {'IP':<18}"
            f"| {'MAC':<20}"
            f"| {'MARCA_OUI':<15}"
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

    # Escanear red
    def escanear_red(self, rango_red):

        scanner = nmap.PortScanner()

        print(f"\nEscaneando red: {rango_red}...\n")

        try:

            scanner.scan(hosts=rango_red, arguments='-O -sS -Pn')   
            #scanner.scan(hosts=rango_red, arguments='-sn -PR -n')

        except nmap.nmap.PortScannerError as e:

            print(f"Error al ejecutar Nmap: {e}")

            return

        for host in scanner.all_hosts():

            if 'mac' in scanner[host]['addresses']:

                ip = host

                mac = scanner[host]['addresses']['mac']

                fabricante = scanner[host]['vendor'].get(
                    mac,
                    'Desconocido'
                )

                # Limpiar caracteres raros
                fabricante = fabricante.encode(
                    'latin-1',
                    errors='ignore'
                ).decode(
                    'utf-8',
                    errors='ignore'
                )

                marca_oui = self.buscar_oui(mac)

                self.guardar_dispositivo(
                    ip,
                    mac,
                    marca_oui,
                    fabricante
                )

    # Cerrar conexión
    def close(self):

        self.conn.close()


if __name__ == "__main__":

    db = EscanerRedDB('red.db')

    red = input(
        "Introduce el rango de red "
        "(ejemplo 192.168.1.0/24): "
    )

    # Escaneo
    db.escanear_red(red)

    # Mostrar tabla bonita
    db.mostrar_dispositivos()

    db.close()