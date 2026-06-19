from getpass import getpass

import requests

from config import DATABASE_PATH, ROUTER_PASS, ROUTER_URL, ROUTER_USER
from network.adapters import get_subnet
from network.nmap_scanner import EscanerRedDB
from routers.kaon_client import KaonRouterClient
from validators import normalize_mac


def crear_cliente_router():
    return KaonRouterClient(
        router_url=ROUTER_URL,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        post_timeout=3,
    )


def imprimir_clientes(clientes):
    if not clientes:
        print("No se encontraron clientes conectados.")
        return

    print("=" * 112)
    print(
        f"| {'MAC':<18}"
        f"| {'IP':<15}"
        f"| {'HOSTNAME':<24}"
        f"| {'RSSI':<8}"
        f"| {'MODO':<6}"
        f"| {'VELOCIDAD':<12}|"
    )
    print("=" * 112)

    for cliente in clientes:
        print(
            f"| {cliente['mac']:<18}"
            f"| {cliente['ip']:<15}"
            f"| {cliente['hostname']:<24}"
            f"| {cliente['rssi']:<8}"
            f"| {cliente['modo']:<6}"
            f"| {cliente['velocidad']:<12}|"
        )

    print("=" * 112)


def listar_clientes_router():
    router = crear_cliente_router()
    imprimir_clientes(router.listar_clientes_24ghz())


def listar_macs_bloqueadas():
    router = crear_cliente_router()
    macs = router.obtener_macs_bloqueadas()

    if not macs:
        print("No hay MAC bloqueadas.")
        return

    print("MAC bloqueadas:")
    for mac in macs:
        print(f"- {mac}")


def bloquear_mac():
    mac = input("MAC a bloquear: ")
    router = crear_cliente_router()
    mac_normalizada = normalize_mac(mac)

    try:
        router.bloquear_mac(mac_normalizada)
    except requests.RequestException:
        verificador = crear_cliente_router()
        if mac_normalizada not in verificador.obtener_macs_bloqueadas():
            raise

    print("Bloqueo listo.")


def desbloquear_mac():
    mac = input("MAC a desbloquear: ")
    router = crear_cliente_router()
    mac_normalizada = normalize_mac(mac)

    try:
        router.desbloquear_mac(mac_normalizada)
    except requests.RequestException:
        verificador = crear_cliente_router()
        if mac_normalizada in verificador.obtener_macs_bloqueadas():
            raise

    print("Desbloqueo listo.")


def preguntar_si_no(pregunta, default=False):
    opciones = "S/n" if default else "s/N"

    while True:
        respuesta = input(f"{pregunta} ({opciones}): ").strip().lower()

        if not respuesta:
            return default

        if respuesta in ("s", "si", "y", "yes"):
            return True

        if respuesta in ("n", "no"):
            return False

        print("Responda con s o n.")


def pedir_texto_no_vacio(pregunta):
    while True:
        valor = input(pregunta).strip()

        if valor:
            return valor

        print("El valor no puede estar vacio.")


def pedir_password_wpa():
    while True:
        password = getpass("Nueva contrasena WPA: ")

        if 8 <= len(password) <= 64:
            return password

        print("La contrasena WPA debe tener entre 8 y 64 caracteres.")


def cargar_config_red_invitados(router):
    config = router.esperar_config_red_invitados(timeout=20, interval=2)

    if config is None:
        raise RuntimeError(
            "El router no esta listo para mostrar la red de invitados. "
            "Espere unos segundos e intente de nuevo."
        )

    return config


def activar_red_invitados():
    router = crear_cliente_router()
    config = cargar_config_red_invitados(router)

    estado = "habilitada" if config["habilitada"] else "deshabilitada"
    ssid = config["ssid"] or "(sin nombre)"
    password = config["password"] or "(sin contrasena configurada)"

    print("\nRed de invitados 2.4GHz")
    print(f"Estado actual: {estado}")

    if preguntar_si_no("Desea cambiar el SSID de la red de invitados?"):
        nuevo_ssid = pedir_texto_no_vacio("Nuevo SSID: ")
    else:
        nuevo_ssid = None
        print(f"SSID actual: {ssid}")

    if not config["password"]:
        print("La red de invitados no tiene contrasena configurada.")
        nueva_password = pedir_password_wpa()
    elif preguntar_si_no("Desea cambiar la contrasena de la red de invitados?"):
        nueva_password = pedir_password_wpa()
    else:
        nueva_password = None
        print(f"Contrasena actual: {password}")

    router.activar_red_invitados(ssid=nuevo_ssid, password=nueva_password)
    ssid_esperado = nuevo_ssid if nuevo_ssid is not None else config["ssid"]
    password_esperada = nueva_password if nueva_password is not None else config["password"]
    config_actualizada = router.esperar_config_red_invitados(
        habilitada=True,
        ssid=ssid_esperado,
        password=password_esperada,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or not config_actualizada["habilitada"]:
        print("\nCambio enviado al router.")
        print("No se pudo confirmar todavia porque el router dejo de responder unos segundos.")
        print("Espere 10 segundos y consulte de nuevo el estado.")
        return

    print("\nRed de invitados activada.")
    print(f"SSID: {config_actualizada['ssid']}")
    print(f"Contrasena: {config_actualizada['password']}")


def desactivar_red_invitados():
    router = crear_cliente_router()
    config = cargar_config_red_invitados(router)
    ssid = config["ssid"] or "(sin nombre)"

    print("\nRed de invitados 2.4GHz")
    print(f"Estado actual: {'habilitada' if config['habilitada'] else 'deshabilitada'}")
    print(f"SSID: {ssid}")

    if not config["habilitada"]:
        print("La red de invitados ya esta desactivada.")
        return

    if not preguntar_si_no("Desea desactivar la red de invitados?"):
        print("Operacion cancelada.")
        return

    router.desactivar_red_invitados()
    config_actualizada = router.esperar_config_red_invitados(
        habilitada=False,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or config_actualizada["habilitada"]:
        print("Cambio enviado al router.")
        print("No se pudo confirmar todavia porque el router dejo de responder unos segundos.")
        print("Espere 10 segundos y consulte de nuevo el estado.")
        return

    print("Red de invitados desactivada.")


def escanear_con_nmap():
    subnet = get_subnet()

    if subnet is None:
        print("No se pudo detectar la subred local.")
        return

    db = EscanerRedDB(str(DATABASE_PATH))

    try:
        db.escanear_red(str(subnet))
        db.mostrar_dispositivos()
    finally:
        db.close()


def main():
    print("Cliente KAON: confirmacion automatica de timeout activa.")

    while True:
        print("\n" + "=" * 44)
        print("Gestor WiFi KAON")
        print("=" * 44)
        print("1. Clientes conectados")
        print("2. Control de acceso: ver MAC bloqueadas")
        print("3. Control de acceso: bloquear MAC")
        print("4. Control de acceso: desbloquear MAC")
        print("5. Red de invitados 2.4GHz: activar")
        print("6. Red de invitados 2.4GHz: desactivar")
        print("7. Escanear red con Nmap")
        print("0. Salir")

        choice = input("Seleccione una opcion: ").strip()

        try:
            if choice == "1":
                listar_clientes_router()
            elif choice == "2":
                listar_macs_bloqueadas()
            elif choice == "3":
                bloquear_mac()
            elif choice == "4":
                desbloquear_mac()
            elif choice == "5":
                activar_red_invitados()
            elif choice == "6":
                desactivar_red_invitados()
            elif choice == "7":
                escanear_con_nmap()
            elif choice == "0":
                break
            else:
                print("Opcion no valida.")
        except Exception as error:
            print(f"Error: {error}")


if __name__ == "__main__":
    main()
