"""Servidor HTTP local y API JSON para el panel de administracion.

El modulo expone archivos estaticos desde `view/` y rutas `/api/` para consultar
dispositivos, guardar alias, bloquear o desbloquear MAC, administrar la red de
invitados y lanzar escaneos Nmap. El servidor esta pensado para uso local, por
eso utiliza `ThreadingHTTPServer` y un `BaseHTTPRequestHandler` ligero en lugar
de un framework web completo.
"""

import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

from app.device_store import get_aliases, list_scanned_devices, save_alias
from app.site_blocking_profiles import (
    PARENTAL_HARDENING_RULES,
    SITE_BLOCKING_PROFILES,
    get_site_blocking_profile,
)
from config import BASE_DIR, DATABASE_PATH, ROUTER_PASS, ROUTER_URL, ROUTER_USER
from network.adapters import get_subnet
from network.nmap_scanner import EscanerRedDB
from routers.kaon_client import KaonRouterClient
from validators import is_valid_mac, normalize_mac


VIEW_DIR = BASE_DIR / "view"


def crear_cliente_router():
    """Construye un cliente KAON con la configuracion global del proyecto."""

    return KaonRouterClient(
        router_url=ROUTER_URL,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        post_timeout=3,
    )


def infer_device_type(hostname="", fabricante=""):
    """Clasifica un dispositivo por palabras clave de hostname o fabricante."""

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
    """Determina el nombre visible priorizando alias, hostname e IP."""

    mac = normalize_mac(device.get("mac", ""))
    hostname = device.get("hostname") or device.get("nombre") or ""
    alias = aliases.get(mac)

    if alias:
        return alias

    if hostname and hostname.lower() != "desconocido":
        return hostname

    return device.get("ip") or mac or "Dispositivo sin nombre"


def normalize_device(device, aliases, blocked_macs=None, source="router"):
    """Convierte datos de router o base local al contrato usado por el frontend."""

    blocked_macs = blocked_macs or set()
    mac = normalize_mac(device.get("mac", ""))
    hostname = device.get("hostname") or "Desconocido"
    fabricante = device.get("fabricante", "")
    source = device.get("source", source)

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
        "band": device.get("band", ""),
        "network": device.get("network", ""),
    }


def _device_identity(device):
    """Devuelve una clave estable para deduplicar dispositivos por MAC o IP."""

    mac = normalize_mac(device.get("mac", ""))

    if mac:
        return f"mac:{mac}"

    ip = (device.get("ip") or "").strip()

    if ip:
        return f"ip:{ip}"

    return None


def _is_unknown_hostname(hostname):
    """Indica si un hostname no aporta informacion util al panel."""

    return not hostname or hostname.strip().lower() == "desconocido"


def merge_router_and_scanned_devices(router_clients, scanned_devices):
    """Une clientes del router y dispositivos Nmap sin repetir MAC."""

    merged = {}
    ordered_keys = []

    for client in router_clients:
        item = {**client, "source": "router"}
        key = _device_identity(item)

        if not key:
            continue

        merged[key] = item
        ordered_keys.append(key)

    for scanned in scanned_devices:
        item = {**scanned, "source": "database"}
        key = _device_identity(item)

        if not key:
            continue

        if key not in merged:
            merged[key] = item
            ordered_keys.append(key)
            continue

        current = merged[key]
        current["source"] = "router+nmap"

        if not current.get("ip") and item.get("ip"):
            current["ip"] = item["ip"]

        if _is_unknown_hostname(current.get("hostname")) and not _is_unknown_hostname(item.get("hostname")):
            current["hostname"] = item["hostname"]

        if not current.get("fabricante") and item.get("fabricante"):
            current["fabricante"] = item["fabricante"]

    return [merged[key] for key in ordered_keys]


def _parental_rule_denies(rule):
    """Indica si una regla de control parental bloquea trafico."""

    action = (rule.get("accion") or "").strip().lower()
    return action.startswith("deneg") or action.startswith("deny")


def _parental_rule_matches_mac(rule, mac):
    """Compara la MAC destino de una regla con el alcance solicitado."""

    return normalize_mac(rule.get("mac", "")) == normalize_mac(mac or "")


def public_error_message(error):
    """Convierte errores tecnicos del router en mensajes seguros para la UI."""

    message = str(error)

    if "HTTPConnectionPool" in message or "WinError 10013" in message:
        return (
            "No se pudo conectar con el router 192.168.1.1. "
            "Revise que el router este accesible y que Python tenga permiso de red local."
        )

    if "timed out" in message.lower() or "timeout" in message.lower():
        return "El router tardo demasiado en responder. Intente actualizar en unos segundos."

    if "401" in message:
        return "El router rechazo las credenciales. Revise usuario y contrasena."

    return message


def _site_profile_response(profile, rules=None, mac=""):
    """Convierte un perfil de bloqueo al contrato usado por el frontend."""

    rules = rules or []
    domains = list(dict.fromkeys(profile["domains"]))
    blocked_domains = {
        rule.get("url")
        for rule in rules
        if _parental_rule_denies(rule) and _parental_rule_matches_mac(rule, mac)
    }
    matched = [domain for domain in domains if domain in blocked_domains]
    blocked_count = len(matched)

    if blocked_count == 0:
        state = "available"
    elif blocked_count == len(domains):
        state = "blocked"
    else:
        state = "partial"

    return {
        "id": profile["id"],
        "name": profile["name"],
        "short": profile["short"],
        "category": profile["category"],
        "description": profile["description"],
        "theme": profile["theme"],
        "icon": profile.get("icon", ""),
        "domains_count": len(domains),
        "blocked_count": blocked_count,
        "state": state,
        "blocked": state == "blocked",
    }


def site_profiles_response(rules=None, mac=""):
    """Devuelve todos los perfiles con estado calculado."""

    return [
        _site_profile_response(profile, rules=rules, mac=mac)
        for profile in SITE_BLOCKING_PROFILES
    ]


class WebHandler(BaseHTTPRequestHandler):
    """Manejador HTTP que sirve el panel y sus rutas JSON."""

    server_version = "GestorWiFiWeb/1.0"

    def do_GET(self):
        """Despacha solicitudes GET entre API JSON y archivos estaticos."""

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

        if parsed.path == "/api/parental/sites":
            params = parse_qs(parsed.query)
            self.handle_parental_sites(params.get("mac", [""])[0])
            return

        self.serve_static(parsed.path)

    def do_POST(self):
        """Despacha operaciones de escritura recibidas por HTTP POST."""

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

            if parsed.path == "/api/parental/block":
                self.handle_parental_action(block=True)
                return

            if parsed.path == "/api/parental/unblock":
                self.handle_parental_action(block=False)
                return

            self.respond_json({"ok": False, "error": "Ruta no encontrada."}, status=404)
        except Exception as error:
            self.respond_json({"ok": False, "error": public_error_message(error)}, status=500)

    def handle_devices(self):
        """Responde con clientes WiFi y dispositivos detectados por Nmap."""

        aliases = get_aliases()
        scanned_devices = list_scanned_devices()

        try:
            router = crear_cliente_router()
            clients = router.listar_clientes_todas_las_bandas()
            blocked_macs = set(router.obtener_macs_bloqueadas_todas_las_bandas())
            combined_devices = merge_router_and_scanned_devices(clients, scanned_devices)
            devices = [
                normalize_device(device, aliases, blocked_macs)
                for device in combined_devices
            ]

            self.respond_json({
                "ok": True,
                "source": "router+nmap",
                "devices": devices,
                "blocked_macs": sorted(blocked_macs),
                "router_count": len(clients),
                "scanned_count": len(scanned_devices),
            })
        except Exception as error:
            scanned = [
                normalize_device(device, aliases, source="database")
                for device in scanned_devices
            ]
            self.respond_json({
                "ok": True,
                "source": "database",
                "warning": public_error_message(error),
                "devices": scanned,
                "blocked_macs": [],
            })

    def handle_blocked(self):
        """Responde con la lista de MAC actualmente bloqueadas en el router."""

        router = crear_cliente_router()
        self.respond_json({"ok": True, "blocked_macs": router.obtener_macs_bloqueadas()})

    def handle_guest_config(self, band):
        """Responde con la configuracion de red de invitados de una banda."""

        router = crear_cliente_router()
        self.respond_json({
            "ok": True,
            "band": band,
            "guest": router.obtener_config_red_invitados(band=band),
        })

    def handle_scanned_devices(self):
        """Responde con dispositivos historicos guardados por el escaner Nmap."""

        aliases = get_aliases()
        devices = [
            normalize_device(device, aliases, source="database")
            for device in list_scanned_devices()
        ]
        self.respond_json({"ok": True, "devices": devices})

    def handle_parental_sites(self, mac=""):
        """Responde con perfiles de control parental y su estado actual."""

        mac = normalize_mac(mac or "")

        if mac and not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        try:
            router = crear_cliente_router()
            rules = router.obtener_reglas_control_parental()
            self.respond_json({
                "ok": True,
                "profiles": site_profiles_response(rules=rules, mac=mac),
                "mac": mac,
                "source": "router",
            })
        except Exception as error:
            self.respond_json({
                "ok": True,
                "profiles": site_profiles_response(mac=mac),
                "mac": mac,
                "source": "catalog",
                "warning": public_error_message(error),
            })

    def handle_save_alias(self):
        """Valida y persiste un alias visible asociado a una MAC."""

        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        alias = save_alias(mac, payload.get("alias", ""))
        self.respond_json({"ok": True, "device": alias})

    def handle_block_device(self):
        """Bloquea una MAC desde la API y confirma el estado si hay timeout."""

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
        """Desbloquea una MAC desde la API y confirma el estado si hay timeout."""

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

    def handle_parental_action(self, block):
        """Bloquea o desbloquea un perfil de sitios en control parental."""

        payload = self.read_json()
        profile = get_site_blocking_profile(payload.get("profile_id", ""))
        mac = normalize_mac(payload.get("mac", "") or "")
        hardening = bool(payload.get("hardening"))

        if mac and not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        router = crear_cliente_router()

        if block:
            result = router.bloquear_dominios_control_parental(
                profile["domains"],
                mac=mac,
                descripcion=profile["description"],
            )

            if hardening:
                result["refuerzo"] = router.bloquear_reglas_control_parental(
                    PARENTAL_HARDENING_RULES,
                    mac=mac,
                )

            message = f"{profile['name']} bloqueado."
        else:
            result = router.desbloquear_dominios_control_parental(
                profile["domains"],
                mac=mac,
            )

            if hardening:
                result["refuerzo"] = router.desbloquear_reglas_control_parental(
                    PARENTAL_HARDENING_RULES,
                    mac=mac,
                )

            message = f"{profile['name']} desbloqueado."

        warning = ""

        try:
            rules = router.obtener_reglas_control_parental()
        except Exception as error:
            rules = []
            warning = public_error_message(error)

        response = {
            "ok": True,
            "message": message,
            "profile": _site_profile_response(profile, rules=rules, mac=mac),
            "profiles": site_profiles_response(rules=rules, mac=mac),
            "result": result,
        }

        if warning:
            response["warning"] = warning

        self.respond_json(response)

    def handle_update_guest(self):
        """Activa o desactiva la red de invitados con los datos recibidos."""

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
        """Ejecuta Nmap sobre la subred local y devuelve dispositivos guardados."""

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

        self.handle_devices()

    def serve_static(self, requested_path):
        """Sirve archivos de `view/` evitando traversal fuera del directorio."""

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
        """Lee y decodifica el cuerpo JSON de la solicitud HTTP actual."""

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw_body or "{}")

    def respond_json(self, payload, status=200):
        """Serializa una respuesta JSON con cabeceras sin cache."""

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Redirige el log HTTP al formato simple del servidor local."""

        print(f"[web] {self.address_string()} - {format % args}")


def main():
    """Configura argumentos CLI y ejecuta el servidor HTTP local."""

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
