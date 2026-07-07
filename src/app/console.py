"""Menu interactivo de administracion local para routers KAON.

La consola ofrece operaciones directas sobre el router: listar clientes, aplicar
filtros MAC, configurar redes primaria e invitados por banda y ejecutar un
escaneo Nmap sobre la subred local. Cada accion delega la comunicacion HTTP al
cliente `KaonRouterClient` y centraliza las confirmaciones necesarias para evitar
cambios accidentales.
"""

from getpass import getpass

import requests

from config import DATABASE_PATH, ROUTER_PASS, ROUTER_URL, ROUTER_USER
from network.adapters import get_subnet
from network.nmap_scanner import EscanerRedDB
from routers.kaon_client import KaonRouterClient
from validators import is_valid_mac, normalize_mac, normalize_url_keyword


PARENTAL_CONTROL_PROFILES = {
    "1": {
        "nombre": "Facebook / Messenger",
        "descripcion": "Bloqueo Facebook",
        "dominios": (
            "facebook.com",
            "www.facebook.com",
            "m.facebook.com",
            "mbasic.facebook.com",
            "graph.facebook.com",
            "connect.facebook.net",
            "facebook.net",
            "fb.com",
            "fbcdn.net",
            "fbsbx.com",
            "messenger.com",
        ),
    },
    "2": {
        "nombre": "YouTube",
        "descripcion": "Bloqueo YouTube",
        "dominios": (
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
            "youtubei.googleapis.com",
            "youtube.googleapis.com",
            "youtube-nocookie.com",
        ),
    },
    "3": {
        "nombre": "Free Fire",
        "descripcion": "Bloqueo FreeFire",
        "dominios": (
            "freefiremobile.com",
            "ff.garena.com",
            "garena.com",
            "garenanow.com",
            "garenanow.com.br",
        ),
    },
    "4": {
        "nombre": "Clash Royale / Supercell",
        "descripcion": "Bloqueo Supercell",
        "dominios": (
            "clashroyale.com",
            "supercell.com",
            "supercellgames.com",
        ),
    },
}


def crear_cliente_router():
    """Construye un cliente KAON con credenciales y URL de configuracion."""

    return KaonRouterClient(
        router_url=ROUTER_URL,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        post_timeout=3,
    )


def imprimir_clientes(clientes):
    """Muestra una tabla de clientes conectados obtenidos desde el router."""

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
    """Consulta el router e imprime los clientes WiFi de la banda 2.4 GHz."""

    router = crear_cliente_router()
    imprimir_clientes(router.listar_clientes_24ghz())


def listar_macs_bloqueadas():
    """Imprime la lista de direcciones MAC bloqueadas en el router."""

    router = crear_cliente_router()
    macs = router.obtener_macs_bloqueadas()

    if not macs:
        print("No hay MAC bloqueadas.")
        return

    print("MAC bloqueadas:")
    for mac in macs:
        print(f"- {mac}")


def listar_reglas_control_parental():
    """Imprime las reglas actuales de `ParentalControl` del router."""

    router = crear_cliente_router()
    reglas = router.obtener_reglas_control_parental()

    if not reglas:
        print("No hay reglas de control parental.")
        return

    print("=" * 122)
    print(
        f"| {'#':<3}"
        f"| {'DESCRIPCION':<22}"
        f"| {'MAC':<18}"
        f"| {'DOMINIO':<32}"
        f"| {'PROTOCOLO':<9}"
        f"| {'ACCION':<10}|"
    )
    print("=" * 122)

    for regla in reglas:
        mac = regla["mac"] or "TODAS"
        print(
            f"| {regla['indice']:<3}"
            f"| {regla['descripcion'][:22]:<22}"
            f"| {mac:<18}"
            f"| {regla['url'][:32]:<32}"
            f"| {regla['protocolo']:<9}"
            f"| {regla['accion']:<10}|"
        )

    print("=" * 122)


def pedir_mac_opcional(pregunta="MAC del dispositivo (Enter para aplicar a todos): "):
    """Solicita una MAC opcional para reglas de control parental."""

    while True:
        mac = input(pregunta).strip()

        if not mac:
            return None

        mac = normalize_mac(mac)

        if is_valid_mac(mac):
            return mac

        print("La MAC no es valida. Use el formato AA:BB:CC:DD:EE:FF.")


def seleccionar_perfil_control_parental():
    """Permite elegir un perfil predefinido o dominios personalizados."""

    print("\nPerfiles disponibles:")

    for key, profile in PARENTAL_CONTROL_PROFILES.items():
        print(f"{key}. {profile['nombre']}")

    print("5. Dominios personalizados")
    print("0. Cancelar")

    choice = input("Seleccione una opcion: ").strip()

    if choice == "0":
        return None

    if choice in PARENTAL_CONTROL_PROFILES:
        return PARENTAL_CONTROL_PROFILES[choice]

    if choice == "5":
        raw_domains = pedir_texto_no_vacio(
            "Dominios separados por coma (ej: facebook.com,fbcdn.net): "
        )
        dominios = [
            normalize_url_keyword(domain)
            for domain in raw_domains.replace(";", ",").split(",")
            if domain.strip()
        ]

        return {
            "nombre": "Personalizado",
            "descripcion": "Bloqueo web",
            "dominios": tuple(dominios),
        }

    print("Opcion no valida.")
    return None


def bloquear_control_parental():
    """Crea reglas de control parental para un perfil o dominios indicados."""

    profile = seleccionar_perfil_control_parental()

    if profile is None:
        print("Operacion cancelada.")
        return

    mac = pedir_mac_opcional()
    alcance = f"solo para {mac}" if mac else "para todos los dispositivos"

    print(f"\nPerfil: {profile['nombre']}")
    print(f"Alcance: {alcance}")
    print("Protocolo: BOTH (TCP y UDP)")

    if not preguntar_si_no("Desea crear estas reglas de control parental?"):
        print("Operacion cancelada.")
        return

    router = crear_cliente_router()
    resultado = router.bloquear_dominios_control_parental(
        profile["dominios"],
        mac=mac,
        descripcion=profile["descripcion"],
    )

    print("\nControl parental actualizado.")

    if resultado["creadas"]:
        print("Reglas creadas:")
        for dominio in resultado["creadas"]:
            print(f"- {dominio}")

    if resultado["omitidas"]:
        print("Reglas ya existentes:")
        for dominio in resultado["omitidas"]:
            print(f"- {dominio}")

    if mac:
        print("\nNota para celulares:")
        print("Verifique que el telefono no use MAC aleatoria/privada en esta red WiFi.")
        print("Luego desconecte y reconecte el WiFi para que el router aplique las reglas.")


def desbloquear_control_parental():
    """Elimina reglas de control parental para un perfil o dominios indicados."""

    profile = seleccionar_perfil_control_parental()

    if profile is None:
        print("Operacion cancelada.")
        return

    mac = pedir_mac_opcional(
        "MAC del dispositivo (Enter para reglas globales sin MAC): "
    )
    alcance = f"solo para {mac}" if mac else "reglas globales sin MAC"

    print(f"\nPerfil: {profile['nombre']}")
    print(f"Alcance a desbloquear: {alcance}")

    if not preguntar_si_no("Desea eliminar estas reglas de control parental?"):
        print("Operacion cancelada.")
        return

    router = crear_cliente_router()
    resultado = router.desbloquear_dominios_control_parental(
        profile["dominios"],
        mac=mac,
    )

    print("\nControl parental actualizado.")

    if resultado["eliminadas"]:
        print("Reglas eliminadas:")
        for dominio in resultado["eliminadas"]:
            print(f"- {dominio}")

    if resultado["no_encontradas"]:
        print("Reglas no encontradas para ese alcance:")
        for dominio in resultado["no_encontradas"]:
            print(f"- {dominio}")


def bloquear_mac():
    """Solicita una MAC por consola y la agrega al filtro de bloqueo."""

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
    """Solicita una MAC por consola y la elimina del filtro de bloqueo."""

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
    """Pide una confirmacion binaria y devuelve `True` o `False`."""

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
    """Solicita texto obligatorio hasta recibir un valor no vacio."""

    while True:
        valor = input(pregunta).strip()

        if valor:
            return valor

        print("El valor no puede estar vacio.")


def pedir_password_wpa():
    """Solicita una contrasena WPA valida para redes WiFi."""

    while True:
        password = getpass("Nueva contrasena WPA: ")

        if 8 <= len(password) <= 64:
            return password

        print("La contrasena WPA debe tener entre 8 y 64 caracteres.")


def cargar_config_red_invitados(router, band):
    """Espera y devuelve la configuracion actual de la red de invitados."""

    config = router.esperar_config_red_invitados(band=band, timeout=20, interval=2)

    if config is None:
        raise RuntimeError(
            f"El router no esta listo para mostrar la red de invitados {band} GHz. "
            "Espere unos segundos e intente de nuevo."
        )

    return config


def cargar_config_red_primaria(router, band):
    """Espera y devuelve la configuracion actual de la red primaria."""

    config = router.esperar_config_red_primaria(band=band, timeout=20, interval=2)

    if config is None:
        raise RuntimeError(
            f"El router no esta listo para mostrar la red primaria {band} GHz. "
            "Espere unos segundos e intente de nuevo."
        )

    return config


def cambiar_ssid_red_primaria(band, etiqueta):
    """Permite cambiar el SSID de la red primaria en la banda indicada."""

    router = crear_cliente_router()
    config = cargar_config_red_primaria(router, band)
    ssid_actual = config["ssid"] or "(sin nombre)"

    print(f"\nRed primaria {etiqueta}")
    print(f"SSID actual: {ssid_actual}")

    nuevo_ssid = pedir_texto_no_vacio("Nuevo SSID: ")

    if not preguntar_si_no("Desea aplicar este nuevo SSID a la red primaria?"):
        print("Operacion cancelada.")
        return

    router.cambiar_ssid_red_primaria(nuevo_ssid, band=band)
    config_actualizada = router.esperar_config_red_primaria(
        ssid=nuevo_ssid,
        band=band,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or config_actualizada["ssid"] != nuevo_ssid:
        print("\nCambio enviado al router.")
        print("No se pudo confirmar todavia porque el router dejo de responder unos segundos.")
        print("Espere 10 segundos y consulte de nuevo el estado.")
        return

    print("\nSSID de la red primaria actualizado.")
    print(f"SSID: {config_actualizada['ssid']}")


def cambiar_password_red_primaria(band, etiqueta):
    """Permite cambiar la contrasena WPA de la red primaria indicada."""

    router = crear_cliente_router()
    config = cargar_config_red_primaria(router, band)
    password_actual = config["password"] or "(sin contrasena configurada)"

    print(f"\nRed primaria {etiqueta}")
    print(f"Contrasena actual: {password_actual}")

    nueva_password = pedir_password_wpa()

    if not preguntar_si_no("Desea aplicar esta nueva contrasena a la red primaria?"):
        print("Operacion cancelada.")
        return

    router.cambiar_password_red_primaria(nueva_password, band=band)
    config_actualizada = router.esperar_config_red_primaria(
        password=nueva_password,
        band=band,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or config_actualizada["password"] != nueva_password:
        print("\nCambio enviado al router.")
        print("No se pudo confirmar todavia porque el router dejo de responder unos segundos.")
        print("Espere 10 segundos y consulte de nuevo el estado.")
        return

    print("\nContrasena de la red primaria actualizada.")


def configurar_ocultar_ssid_red_primaria(band, etiqueta):
    """Permite mostrar u ocultar la emision del SSID de la red primaria."""

    router = crear_cliente_router()
    config = cargar_config_red_primaria(router, band)

    print(f"\nRed primaria {etiqueta}")
    print(f"SSID actual: {config['ssid'] or '(sin nombre)'}")

    if config["oculto"] is None:
        print("Estado actual: no se pudo leer si el SSID esta oculto.")
    else:
        estado = "oculto" if config["oculto"] else "visible"
        print(f"Estado actual: SSID {estado}")

    ocultar = preguntar_si_no("Desea ocultar el SSID de la red primaria?", default=True)

    if not preguntar_si_no("Desea aplicar este cambio de visibilidad?"):
        print("Operacion cancelada.")
        return

    router.configurar_ocultar_ssid_red_primaria(ocultar, band=band)
    config_actualizada = router.esperar_config_red_primaria(
        oculto=ocultar,
        band=band,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or config_actualizada["oculto"] != ocultar:
        print("\nCambio enviado al router.")
        print("No se pudo confirmar todavia porque el router dejo de responder unos segundos.")
        print("Espere 10 segundos y consulte de nuevo el estado.")
        return

    estado = "oculto" if config_actualizada["oculto"] else "visible"
    print(f"\nSSID de la red primaria ahora esta {estado}.")


def activar_red_invitados(band, etiqueta):
    """Activa la red de invitados y opcionalmente actualiza SSID y clave."""

    router = crear_cliente_router()
    config = cargar_config_red_invitados(router, band)

    estado = "habilitada" if config["habilitada"] else "deshabilitada"
    ssid = config["ssid"] or "(sin nombre)"
    password = config["password"] or "(sin contrasena configurada)"

    print(f"\nRed de invitados {etiqueta}")
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

    router.activar_red_invitados(ssid=nuevo_ssid, password=nueva_password, band=band)
    ssid_esperado = nuevo_ssid if nuevo_ssid is not None else config["ssid"]
    password_esperada = nueva_password if nueva_password is not None else config["password"]
    config_actualizada = router.esperar_config_red_invitados(
        habilitada=True,
        ssid=ssid_esperado,
        password=password_esperada,
        band=band,
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


def desactivar_red_invitados(band, etiqueta):
    """Desactiva la red de invitados despues de confirmar la accion."""

    router = crear_cliente_router()
    config = cargar_config_red_invitados(router, band)
    ssid = config["ssid"] or "(sin nombre)"

    print(f"\nRed de invitados {etiqueta}")
    print(f"Estado actual: {'habilitada' if config['habilitada'] else 'deshabilitada'}")
    print(f"SSID: {ssid}")

    if not config["habilitada"]:
        print("La red de invitados ya esta desactivada.")
        return

    if not preguntar_si_no("Desea desactivar la red de invitados?"):
        print("Operacion cancelada.")
        return

    router.desactivar_red_invitados(band=band)
    config_actualizada = router.esperar_config_red_invitados(
        habilitada=False,
        band=band,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or config_actualizada["habilitada"]:
        print("Cambio enviado al router.")
        print("No se pudo confirmar todavia porque el router dejo de responder unos segundos.")
        print("Espere 10 segundos y consulte de nuevo el estado.")
        return

    print("Red de invitados desactivada.")


def alternar_red_invitados(band, etiqueta):
    """Activa o desactiva la red de invitados segun su estado actual."""

    router = crear_cliente_router()
    config = cargar_config_red_invitados(router, band)

    if config["habilitada"]:
        desactivar_red_invitados(band, etiqueta)
    else:
        activar_red_invitados(band, etiqueta)


def alternar_red_primaria(band, etiqueta):
    """Activa o desactiva una red primaria preservando al menos una banda."""

    otra_banda = "5" if band == "2.4" else "2.4"
    otra_etiqueta = "5 GHz" if otra_banda == "5" else "2.4 GHz"
    router = crear_cliente_router()
    config = cargar_config_red_primaria(router, band)
    otra_config = cargar_config_red_primaria(router, otra_banda)

    estado = "habilitada" if config["habilitada"] else "deshabilitada"
    print(f"\nRed primaria {etiqueta}")
    print(f"Estado actual: {estado}")
    print(f"SSID actual: {config['ssid'] or '(sin nombre)'}")

    if not config["habilitada"]:
        if not preguntar_si_no("Desea activar esta red primaria?"):
            print("Operacion cancelada.")
            return

        router.activar_red_primaria(band=band)
        config_actualizada = router.esperar_config_red_primaria(
            habilitada=True,
            band=band,
            timeout=25,
            interval=2,
        )

        if config_actualizada is None or not config_actualizada["habilitada"]:
            print("Cambio enviado al router, pero no se pudo confirmar todavia.")
            return

        print(f"Red primaria {etiqueta} activada.")
        return

    if not preguntar_si_no("Desea desactivar esta red primaria?"):
        print("Operacion cancelada.")
        return

    if not otra_config["habilitada"]:
        print(f"No se pueden apagar ambas redes primarias a la vez.")
        print(f"La red primaria {otra_etiqueta} esta deshabilitada.")

        if not preguntar_si_no(f"Desea activar la red {otra_etiqueta} y apagar {etiqueta}?"):
            print("Operacion cancelada.")
            return

        router.activar_red_primaria(band=otra_banda)
        otra_actualizada = router.esperar_config_red_primaria(
            habilitada=True,
            band=otra_banda,
            timeout=25,
            interval=2,
        )

        if otra_actualizada is None or not otra_actualizada["habilitada"]:
            print(f"No se pudo confirmar que la red {otra_etiqueta} quedara activa.")
            print("Por seguridad no se apago la red actual.")
            return

    router.desactivar_red_primaria(band=band)
    config_actualizada = router.esperar_config_red_primaria(
        habilitada=False,
        band=band,
        timeout=25,
        interval=2,
    )

    if config_actualizada is None or config_actualizada["habilitada"]:
        print("Cambio enviado al router, pero no se pudo confirmar todavia.")
        return

    print(f"Red primaria {etiqueta} desactivada.")


def configurar_banda_wifi(band, etiqueta):
    """Muestra el submenu de configuracion para una banda WiFi especifica."""

    while True:
        print("\n" + "=" * 44)
        print(f"Configurar red {etiqueta}")
        print("=" * 44)
        print("1. Cambiar SSID")
        print("2. Cambiar contrasena")
        print("3. Mostrar / Ocultar el SSID")
        print("4. Activar / Desactivar la red de invitados")
        print("5. Activar / Desactivar la red primaria")
        print("0. Volver")

        choice = input("Seleccione una opcion: ").strip()

        if choice == "1":
            cambiar_ssid_red_primaria(band, etiqueta)
        elif choice == "2":
            cambiar_password_red_primaria(band, etiqueta)
        elif choice == "3":
            configurar_ocultar_ssid_red_primaria(band, etiqueta)
        elif choice == "4":
            alternar_red_invitados(band, etiqueta)
        elif choice == "5":
            alternar_red_primaria(band, etiqueta)
        elif choice == "0":
            break
        else:
            print("Opcion no valida.")


def escanear_con_nmap():
    """Detecta la subred local, ejecuta Nmap y muestra dispositivos guardados."""

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
    """Ejecuta el bucle principal del menu interactivo de consola."""

    print("Cliente KAON: confirmacion automatica de timeout activa.")

    while True:
        print("\n" + "=" * 44)
        print("Gestor WiFi KAON")
        print("=" * 44)
        print("1. Clientes conectados")
        print("2. Control de acceso: ver MAC bloqueadas")
        print("3. Control de acceso: bloquear MAC")
        print("4. Control de acceso: desbloquear MAC")
        print("5. Configurar la red 2.4 GHz")
        print("6. Configurar la red 5 GHz")
        print("7. Escanear red con Nmap")
        print("8. Control parental: ver reglas")
        print("9. Control parental: bloquear sitios o juegos")
        print("10. Control parental: desbloquear sitios o juegos")
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
                configurar_banda_wifi("2.4", "2.4 GHz")
            elif choice == "6":
                configurar_banda_wifi("5", "5 GHz")
            elif choice == "7":
                escanear_con_nmap()
            elif choice == "8":
                listar_reglas_control_parental()
            elif choice == "9":
                bloquear_control_parental()
            elif choice == "10":
                desbloquear_control_parental()
            elif choice == "0":
                break
            else:
                print("Opcion no valida.")
        except Exception as error:
            print(f"Error: {error}")


if __name__ == "__main__":
    main()
