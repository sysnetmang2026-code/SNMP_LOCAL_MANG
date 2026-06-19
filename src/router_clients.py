from config import ROUTER_PASS, ROUTER_URL, ROUTER_USER
from routers.kaon_client import KaonRouterClient


def obtener_clientes_router():
    router = KaonRouterClient(
        router_url=ROUTER_URL,
        username=ROUTER_USER,
        password=ROUTER_PASS,
    )
    return router.listar_clientes_24ghz()

