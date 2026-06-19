from config import ROUTER_PASS, ROUTER_URL, ROUTER_USER
from routers.kaon_client import KaonRouterClient


def crear_cliente_router():
    return KaonRouterClient(
        router_url=ROUTER_URL,
        username=ROUTER_USER,
        password=ROUTER_PASS,
    )


def bloquear_dispositivo(mac):
    router = crear_cliente_router()
    router.bloquear_mac(mac)
    return True, "Bloqueo listo."


def desbloquear_dispositivo(mac):
    router = crear_cliente_router()
    router.desbloquear_mac(mac)
    return True, "Desbloqueo listo."


if __name__ == "__main__":
    mac_dispositivo = input("Ingrese la MAC del dispositivo: ")
    accion = input("Escriba B para bloquear o D para desbloquear: ").strip().upper()

    try:
        if accion == "B":
            correcto, respuesta = bloquear_dispositivo(mac_dispositivo)
        elif accion == "D":
            correcto, respuesta = desbloquear_dispositivo(mac_dispositivo)
        else:
            correcto, respuesta = False, "Accion no valida."

        print(respuesta)
    except Exception as error:
        print(f"Error: {error}")
