import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

from app.device_store import get_aliases, list_scanned_devices, save_alias
from config import BASE_DIR, DATABASE_PATH, ROUTER_PASS, ROUTER_URL, ROUTER_USER
from network.adapters import get_subnet
from network.nmap_scanner import EscanerRedDB
from routers.kaon_client import KaonRouterClient
from validators import is_valid_mac, normalize_mac


VIEW_DIR = BASE_DIR / "view"


def crear_cliente_router():
    return KaonRouterClient(
        router_url=ROUTER_URL,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        post_timeout=3,
    )


def infer_device_type(hostname="", fabricante=""):
    value = f"{hostname} {fabricante}".lower()

    if any(word in value for word in ("roku", "tv", "chromecast", "smart-tv", "smarttv")):
        return "tv"

    if any(word in value for word in ("desktop", "laptop", "notebook", "pc-", "pc ", "windows")):
        return "pc"

    if any(word in value for word in ("cam", "camera", "camara", "ipcam", "ezviz", "hikvision")):
        return "camera"

    if any(word in value for word in ("printer", "impresora", "epson", "canon", "hp ")):
        return "printer"

    if any(word in value for word in (
        "android",
        "galaxy",
        "iphone",
        "redmi",
        "xiaomi",
        "moto",
        "infinix",
        "huawei",
        "honor",
        "samsung",
        "s23",
    )):
        return "phone"

    return "unknown"


def display_name(device, aliases):
    mac = normalize_mac(device.get("mac", ""))
    hostname = device.get("hostname") or device.get("nombre") or ""
    alias = aliases.get(mac)

    if alias:
        return alias

    if hostname and hostname.lower() != "desconocido":
        return hostname

    return device.get("ip") or mac or "Dispositivo sin nombre"


def normalize_device(device, aliases, blocked_macs=None, source="router"):
    blocked_macs = blocked_macs or set()
    mac = normalize_mac(device.get("mac", ""))
    hostname = device.get("hostname") or "Desconocido"
    fabricante = device.get("fabricante", "")

    return {
        "mac": mac,
        "ip": device.get("ip", ""),
        "hostname": hostname,
        "alias": aliases.get(mac, ""),
        "name": display_name(device, aliases),
        "fabricante": fabricante,
        "rssi": device.get("rssi", ""),
        "modo": device.get("modo", ""),
        "velocidad": device.get("velocidad", ""),
        "duracion": device.get("duracion", ""),
        "type": infer_device_type(hostname, fabricante),
        "blocked": mac in blocked_macs,
        "source": source,
    }


class WebHandler(BaseHTTPRequestHandler):
    server_version = "GestorWiFiWeb/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/devices":
            self.handle_devices()
            return

        if parsed.path == "/api/blocked":
            self.handle_blocked()
            return

        if parsed.path == "/api/guest":
            params = parse_qs(parsed.query)
            self.handle_guest_config(params.get("band", ["2.4"])[0])
            return

        if parsed.path == "/api/scan/devices":
            self.handle_scanned_devices()
            return

        self.serve_static(parsed.path)

    def do_POST(self):
        parsed = urlparse(self.path)

        try:
            if parsed.path == "/api/devices/alias":
                self.handle_save_alias()
                return

            if parsed.path == "/api/devices/block":
                self.handle_block_device()
                return

            if parsed.path == "/api/devices/unblock":
                self.handle_unblock_device()
                return

            if parsed.path == "/api/guest":
                self.handle_update_guest()
                return

            if parsed.path == "/api/scan":
                self.handle_scan()
                return

            self.respond_json({"ok": False, "error": "Ruta no encontrada."}, status=404)
        except Exception as error:
            self.respond_json({"ok": False, "error": str(error)}, status=500)

    def handle_devices(self):
        aliases = get_aliases()

        try:
            router = crear_cliente_router()
            clients = router.listar_clientes_24ghz()
            blocked_macs = set(router.obtener_macs_bloqueadas())
            devices = [
                normalize_device(client, aliases, blocked_macs, source="router")
                for client in clients
            ]

            self.respond_json({
                "ok": True,
                "source": "router",
                "devices": devices,
                "blocked_macs": sorted(blocked_macs),
            })
        except Exception as error:
            scanned = [
                normalize_device(device, aliases, source="database")
                for device in list_scanned_devices()
            ]
            self.respond_json({
                "ok": True,
                "source": "database",
                "warning": str(error),
                "devices": scanned,
                "blocked_macs": [],
            })

    def handle_blocked(self):
        router = crear_cliente_router()
        self.respond_json({"ok": True, "blocked_macs": router.obtener_macs_bloqueadas()})

    def handle_guest_config(self, band):
        router = crear_cliente_router()
        self.respond_json({
            "ok": True,
            "band": band,
            "guest": router.obtener_config_red_invitados(band=band),
        })

    def handle_scanned_devices(self):
        aliases = get_aliases()
        devices = [
            normalize_device(device, aliases, source="database")
            for device in list_scanned_devices()
        ]
        self.respond_json({"ok": True, "devices": devices})

    def handle_save_alias(self):
        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        alias = save_alias(mac, payload.get("alias", ""))
        self.respond_json({"ok": True, "device": alias})

    def handle_block_device(self):
        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        router = crear_cliente_router()

        try:
            router.bloquear_mac(mac)
        except requests.RequestException:
            verifier = crear_cliente_router()
            if mac not in verifier.obtener_macs_bloqueadas():
                raise

        self.respond_json({"ok": True, "message": "Dispositivo bloqueado.", "mac": mac})

    def handle_unblock_device(self):
        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        router = crear_cliente_router()

        try:
            router.desbloquear_mac(mac)
        except requests.RequestException:
            verifier = crear_cliente_router()
            if mac in verifier.obtener_macs_bloqueadas():
                raise

        self.respond_json({"ok": True, "message": "Dispositivo desbloqueado.", "mac": mac})

    def handle_update_guest(self):
        payload = self.read_json()
        router = crear_cliente_router()
        band = payload.get("band", "2.4")
        enabled = bool(payload.get("enabled"))

        if enabled:
            router.activar_red_invitados(
                ssid=payload.get("ssid") or None,
                password=payload.get("password") or None,
                band=band,
            )
            message = "Red de invitados activada."
        else:
            router.desactivar_red_invitados(band=band)
            message = "Red de invitados desactivada."

        self.respond_json({"ok": True, "message": message})

    def handle_scan(self):
        subnet = get_subnet()

        if subnet is None:
            self.respond_json({
                "ok": False,
                "error": "No se pudo detectar la subred local.",
            }, status=400)
            return

        db = EscanerRedDB(str(DATABASE_PATH))

        try:
            db.escanear_red(str(subnet))
        finally:
            db.close()

        self.handle_scanned_devices()

    def serve_static(self, requested_path):
        filename = "panel-red.html" if requested_path in ("", "/") else requested_path.lstrip("/")
        file_path = (VIEW_DIR / filename).resolve()
        view_root = VIEW_DIR.resolve()

        if file_path != view_root and view_root not in file_path.parents:
            self.respond_json({"ok": False, "error": "Archivo no permitido."}, status=403)
            return

        if not file_path.is_file():
            self.respond_json({"ok": False, "error": "Archivo no encontrado."}, status=404)
            return

        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        content = file_path.read_bytes()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def read_json(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw_body or "{}")

    def respond_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"[web] {self.address_string()} - {format % args}")


def main():
    parser = argparse.ArgumentParser(description="Servidor web local del Gestor WiFi KAON")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), WebHandler)
    print(f"Panel web disponible en http://{args.host}:{args.port}")
    print("Presione Ctrl+C para detenerlo.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
