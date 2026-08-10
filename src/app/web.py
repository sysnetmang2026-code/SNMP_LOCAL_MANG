"""Servidor HTTP local y API JSON para el panel de administracion.

El modulo expone archivos estaticos desde `view/` y rutas `/api/` para consultar
dispositivos, guardar alias, bloquear o desbloquear MAC, administrar la red de
invitados y lanzar escaneos Nmap. El servidor esta pensado para uso local, por
eso utiliza `ThreadingHTTPServer` y un `BaseHTTPRequestHandler` ligero en lugar
de un framework web completo.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookies import CookieError, SimpleCookie
import ipaddress
import json
import mimetypes
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time
import unicodedata
from urllib.parse import parse_qs, urlparse

from app.device_store import (
    WIFI_CLIENT_LIMIT_MAX,
    clear_activity_events,
    forget_device,
    get_aliases,
    get_wifi_client_limit,
    get_wifi_client_limits,
    list_activity_events,
    list_presence_devices,
    list_scanned_devices,
    record_audit_event as persist_audit_event,
    record_device_snapshot,
    save_alias,
    set_wifi_client_limit,
)
from app.site_blocking_profiles import (
    PARENTAL_HARDENING_RULES,
    SITE_BLOCKING_PROFILES,
    get_site_blocking_profile,
)
from config import BASE_DIR, DATABASE_PATH, ROUTER_URL
from network.adapters import get_subnet
from network.nmap_scanner import EscanerRedDB, is_router_device
from routers.kaon_client import KaonRouterClient
from validators import is_valid_mac, normalize_mac


VIEW_DIR = BASE_DIR / "view"
AUTH_COOKIE_NAME = "kaon_panel_session"
AUTH_SESSION_TTL_SECONDS = 8 * 60 * 60
AUTH_SESSION_LOCK = threading.RLock()
AUTH_SESSIONS = {}
PING_TIMEOUT_MS = 700
PING_WORKERS = 16
ROUTER_OPERATION_LOCK = threading.RLock()


def record_audit_event(*args, **kwargs):
    """Registra auditoria sin interrumpir la operacion principal si SQLite falla."""

    try:
        return persist_audit_event(*args, **kwargs)
    except Exception as error:
        print(f"[audit] No se pudo guardar el evento: {error}")
        return None


def crear_cliente_router(credentials):
    """Construye un cliente KAON con credenciales de la sesion local."""

    return KaonRouterClient(
        router_url=ROUTER_URL,
        username=credentials.get("username"),
        password=credentials.get("password"),
        post_timeout=3,
    )


def _prune_auth_sessions(now=None):
    """Elimina sesiones locales vencidas de la memoria del servidor."""

    now = now or time.time()
    expired_tokens = [
        token
        for token, session in AUTH_SESSIONS.items()
        if now - session.get("last_seen", 0) > AUTH_SESSION_TTL_SECONDS
    ]

    for token in expired_tokens:
        AUTH_SESSIONS.pop(token, None)


def _auth_cookie_header(token):
    """Construye la cookie opaca usada para recuperar la sesion local."""

    return (
        f"{AUTH_COOKIE_NAME}={token}; Path=/; Max-Age={AUTH_SESSION_TTL_SECONDS}; "
        "HttpOnly; SameSite=Strict"
    )


def _clear_auth_cookie_header():
    """Construye la cabecera para borrar la cookie de sesion."""

    return f"{AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"


def _auth_token_from_cookie(cookie_header):
    """Extrae el token de sesion desde la cabecera Cookie."""

    cookie = SimpleCookie()

    try:
        cookie.load(cookie_header or "")
    except CookieError:
        return ""

    morsel = cookie.get(AUTH_COOKIE_NAME)
    return morsel.value if morsel else ""


def create_auth_session(username, password):
    """Guarda credenciales del router solo en memoria y devuelve un token."""

    now = time.time()
    token = secrets.token_urlsafe(32)

    with AUTH_SESSION_LOCK:
        _prune_auth_sessions(now)
        AUTH_SESSIONS[token] = {
            "username": username,
            "password": password,
            "created_at": now,
            "last_seen": now,
        }

    return token


def get_auth_session(cookie_header):
    """Recupera la sesion local asociada a una cookie valida."""

    token = _auth_token_from_cookie(cookie_header)

    if not token:
        return None

    now = time.time()

    with AUTH_SESSION_LOCK:
        _prune_auth_sessions(now)
        session = AUTH_SESSIONS.get(token)

        if not session:
            return None

        session["last_seen"] = now
        return {**session, "token": token}


def destroy_auth_session(cookie_header):
    """Elimina de memoria la sesion asociada a la cookie actual."""

    token = _auth_token_from_cookie(cookie_header)

    if not token:
        return

    with AUTH_SESSION_LOCK:
        AUTH_SESSIONS.pop(token, None)


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


def without_router(devices):
    """Excluye el router configurado de cualquier lista administrable."""

    return [
        device
        for device in devices
        if not is_router_device(
            device.get("ip", ""),
            device.get("hostname", ""),
            device.get("fabricante", ""),
        )
    ]


def without_router_events(events):
    """Excluye del historial cualquier evento asociado al router."""

    return [
        event
        for event in events
        if not is_router_device(
            event.get("ip", ""),
            event.get("hostname", ""),
            "",
        )
    ]


def audit_device_subject(mac):
    """Devuelve alias o MAC para identificar un equipo en la bitacora."""

    mac = normalize_mac(mac or "")
    return get_aliases().get(mac) or mac or "Dispositivo"


def wifi_change_detail(payload, previous, previous_limit=None):
    """Describe cambios WiFi sin incluir la clave anterior ni la nueva."""

    previous = previous or {}
    changes = []

    if "ssid" in payload:
        ssid = str(payload.get("ssid") or "").strip()

        if ssid != str(previous.get("ssid") or "").strip():
            changes.append(f"SSID cambiado a {ssid or 'sin nombre'}")

    password = str(payload.get("password") or "")

    if password and password != str(previous.get("password") or ""):
        changes.append("contrasena actualizada")

    if "hidden" in payload:
        hidden = bool(payload.get("hidden"))

        if hidden != bool(previous.get("oculto")):
            changes.append("SSID oculto" if hidden else "SSID visible")

    if "enabled" in payload:
        enabled = bool(payload.get("enabled"))

        if enabled != bool(previous.get("habilitada")):
            changes.append("red activada" if enabled else "red desactivada")

    if "max_clients" in payload:
        requested_limit = payload.get("max_clients")

        if str(requested_limit) != str(previous_limit if previous_limit is not None else ""):
            changes.append(f"limite de usuarios: {requested_limit}")

    return "; ".join(changes) or "Configuracion guardada sin diferencias detectadas."


def is_protected_router_mac(mac):
    """Comprueba si una MAC guardada corresponde al router local."""

    mac = normalize_mac(mac or "")

    for device in [*list_scanned_devices(), *list_presence_devices()]:
        if normalize_mac(device.get("mac", "") or "") != mac:
            continue

        if is_router_device(
            device.get("ip", ""),
            device.get("hostname", ""),
            device.get("fabricante", ""),
        ):
            return True

    return False


def local_subnet_label():
    """Devuelve la subred detectada sin interrumpir una lectura si no existe."""

    try:
        subnet = get_subnet()
    except Exception:
        return ""

    return str(subnet) if subnet is not None else ""


def _normalize_netsh_label(value):
    """Normaliza etiquetas de `netsh` en Windows ingles o espanol."""

    normalized = unicodedata.normalize("NFKD", str(value or ""))
    return "".join(
        character
        for character in normalized
        if not unicodedata.combining(character)
    ).strip().lower()


def get_host_wifi_connection():
    """Devuelve SSID, banda e interfaz WiFi usadas por esta computadora."""

    if platform.system().lower() != "windows":
        return {}

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    if result.returncode != 0:
        return {}

    fields = {}

    for raw_line in result.stdout.splitlines():
        if ":" not in raw_line:
            continue

        key, value = raw_line.split(":", 1)
        fields[_normalize_netsh_label(key)] = value.strip()

    state = _normalize_netsh_label(fields.get("estado") or fields.get("state"))

    if state not in ("conectado", "connected"):
        return {}

    ssid = fields.get("ssid", "").strip()

    if not ssid:
        return {}

    band_value = fields.get("banda") or fields.get("band") or ""
    normalized_band = band_value.replace(",", ".")
    band = "5" if "5" in normalized_band else "2.4" if "2.4" in normalized_band else ""
    channel_value = fields.get("canal") or fields.get("channel") or ""
    channel_digits = "".join(character for character in channel_value if character.isdigit())
    channel = int(channel_digits) if channel_digits else None

    if not band and channel is not None:
        band = "2.4" if channel <= 14 else "5"

    signal_value = fields.get("senal") or fields.get("signal") or ""
    signal_digits = "".join(character for character in signal_value if character.isdigit())

    return {
        "ssid": ssid,
        "band": band,
        "channel": channel,
        "interface": fields.get("nombre") or fields.get("name") or "WiFi",
        "signal_percent": int(signal_digits) if signal_digits else None,
    }


def attach_managed_client_limit(config, interface_kind, band):
    """Agrega al contrato WiFi el limite administrado por el panel local."""

    local_limit = get_wifi_client_limit(interface_kind, band)
    native_limit = config.get("limite_clientes")
    native_supported = bool(config.get("limite_clientes_soportado"))

    config["limite_clientes"] = local_limit if local_limit is not None else native_limit
    config["limite_clientes_soportado"] = True
    config["limite_clientes_max"] = WIFI_CLIENT_LIMIT_MAX
    config["limite_clientes_origen"] = (
        "panel" if local_limit is not None or not native_supported else "router"
    )
    config["limite_clientes_administrado"] = local_limit is not None or not native_supported
    return config


def wifi_limit_key_for_client(client):
    """Devuelve `(tipo, banda)` para aplicar limites por interfaz WiFi."""

    band = str(client.get("band") or "").strip()

    if band not in ("2.4", "5"):
        return None

    network_index = str(client.get("network_index") or "0")
    network = str(client.get("network") or "").lower()
    guest = bool(client.get("guest")) or network_index != "0" or "invitados" in network
    return ("guest" if guest else "primary", band)


def enforce_wifi_client_limits(router, clients, blocked_macs):
    """Bloquea equipos que exceden los limites locales por interfaz WiFi."""

    limits = get_wifi_client_limits()

    if not limits or not clients:
        return {"applied": [], "errors": []}

    grouped_clients = {}

    for client in clients:
        key = wifi_limit_key_for_client(client)
        mac = normalize_mac(client.get("mac", "") or "")

        if not key or not mac:
            continue

        grouped_clients.setdefault(key, []).append({**client, "mac": mac})

    applied = []
    errors = []

    for key, limit in limits.items():
        clients_in_interface = grouped_clients.get(key, [])

        if len(clients_in_interface) <= limit:
            continue

        for client in clients_in_interface[limit:]:
            mac = client["mac"]

            if mac in blocked_macs:
                continue

            try:
                router.bloquear_mac(
                    mac,
                    band=client.get("band"),
                    network_index=client.get("network_index") or 0,
                )
                blocked_macs.add(mac)
                applied.append({
                    "mac": mac,
                    "band": client.get("band", ""),
                    "network": client.get("network", ""),
                    "network_index": client.get("network_index", ""),
                    "limit": limit,
                })
            except Exception as error:
                errors.append(
                    f"{client.get('network') or key[0]} {key[1]} GHz/{mac}: "
                    f"{public_error_message(error)}"
                )

    return {"applied": applied, "errors": errors}


def normalize_device(device, aliases, blocked_macs=None, source="router"):
    """Convierte datos de router o base local al contrato usado por el frontend."""

    blocked_macs = blocked_macs or set()
    mac = normalize_mac(device.get("mac", ""))
    hostname = device.get("hostname") or "Desconocido"
    fabricante = device.get("fabricante", "")
    source = device.get("source", source)
    connected = bool(device.get("connected"))
    status = "blocked" if mac in blocked_macs else "connected" if connected else "offline"

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
        "connected": connected,
        "status": status,
        "source": source,
        "band": device.get("band", ""),
        "network": device.get("network", ""),
        "network_index": device.get("network_index", ""),
        "ssid": device.get("ssid", ""),
        "guest": bool(device.get("guest")),
        "first_seen": device.get("first_seen", ""),
        "last_seen": device.get("last_seen", ""),
        "last_checked": device.get("last_checked", ""),
        "last_disconnected": device.get("last_disconnected", ""),
        "reachable_by_ping": bool(device.get("reachable_by_ping")),
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


def _device_ip(device):
    """Devuelve la IP normalizada para comparar registros stale."""

    return str(device.get("ip") or "").strip()


def _is_unknown_hostname(hostname):
    """Indica si un hostname no aporta informacion util al panel."""

    value = str(hostname or "").strip().lower()
    return not value or value in ("desconocido", "unknown", "none", "n/a", "-")


def _prefer_hostname(target, source):
    """Completa el nombre visible con el dato mas util disponible."""

    if _is_unknown_hostname(target.get("hostname")) and not _is_unknown_hostname(source.get("hostname")):
        target["hostname"] = source["hostname"]


def _merge_missing_fields(target, source, fields):
    """Copia metadatos faltantes sin pisar la lectura principal del router."""

    for field in fields:
        if not target.get(field) and source.get(field):
            target[field] = source[field]


def merge_router_and_scanned_devices(router_clients, scanned_devices, known_devices=None):
    """Une clientes del router, Nmap e historial local sin repetir MAC."""

    merged = {}
    ordered_keys = []
    router_ip_owners = {}

    for client in router_clients:
        item = {**client, "source": "router"}
        item["mac"] = normalize_mac(item.get("mac", ""))
        key = _device_identity(item)

        if not key:
            continue

        if key not in merged:
            ordered_keys.append(key)

        merged[key] = item
        ip = _device_ip(item)

        if ip and item.get("mac"):
            router_ip_owners[ip] = item["mac"]

    for scanned in scanned_devices:
        item = {**scanned, "source": "database"}
        item["mac"] = normalize_mac(item.get("mac", ""))
        key = _device_identity(item)

        if not key:
            continue

        ip_owner = router_ip_owners.get(_device_ip(item))

        if ip_owner and ip_owner != item.get("mac"):
            continue

        if key not in merged:
            merged[key] = item
            ordered_keys.append(key)
            continue

        current = merged[key]
        current["source"] = (
            "router+nmap"
            if current.get("source") in ("router", "router+nmap")
            else current.get("source", "database")
        )

        if not current.get("ip") and item.get("ip"):
            current["ip"] = item["ip"]

        _prefer_hostname(current, item)
        _merge_missing_fields(current, item, ("fabricante",))

    for known in known_devices or []:
        item = {**known, "source": "history"}
        item["mac"] = normalize_mac(item.get("mac", ""))
        key = _device_identity(item)

        if not key:
            continue

        ip_owner = router_ip_owners.get(_device_ip(item))

        if ip_owner and ip_owner != item.get("mac"):
            continue

        if key not in merged:
            merged[key] = item
            ordered_keys.append(key)
            continue

        current = merged[key]
        _prefer_hostname(current, item)
        _merge_missing_fields(current, item, (
            "ip",
            "fabricante",
            "band",
            "network",
            "first_seen",
            "last_seen",
            "last_checked",
            "last_disconnected",
        ))

    return [merged[key] for key in ordered_keys]


def _query_bool(params, name, default=True):
    """Interpreta parametros de consulta booleanos."""

    if not params or name not in params:
        return default

    value = str(params.get(name, [default])[0]).strip().lower()
    return value not in ("0", "false", "no", "off")


def _can_ping_ip(ip):
    """Indica si una IP es valida para una prueba ICMP local corta."""

    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False

    return (
        address.version == 4
        and (address.is_private or address.is_link_local)
        and not address.is_loopback
        and not address.is_multicast
        and not address.is_unspecified
    )


def ping_ip(ip, timeout_ms=PING_TIMEOUT_MS):
    """Prueba si una IP responde a un ping rapido."""

    if not _can_ping_ip(ip):
        return False

    if platform.system().lower() == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_seconds = str(max(1, int(timeout_ms / 1000)))
        command = ["ping", "-c", "1", "-W", timeout_seconds, ip]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 0.5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False

    return result.returncode == 0


def apply_connectivity_probe(devices, probe=True):
    """Marca dispositivos activos por router o por ping local."""

    ping_targets = {}
    probe_ip_counts = Counter(
        _device_ip(device)
        for device in devices
        if device.get("source", "") not in ("router", "router+nmap")
        and _can_ping_ip(device.get("ip", ""))
    )

    for index, device in enumerate(devices):
        source = device.get("source", "")

        if source in ("router", "router+nmap"):
            device["connected"] = True
            device["presence_source"] = "router"
            continue

        device["connected"] = False
        device["presence_source"] = "history"

        if (
            probe
            and _can_ping_ip(device.get("ip", ""))
            and probe_ip_counts[_device_ip(device)] == 1
        ):
            ping_targets[index] = device["ip"]

    if not ping_targets:
        return

    with ThreadPoolExecutor(max_workers=min(PING_WORKERS, len(ping_targets))) as executor:
        futures = {
            executor.submit(ping_ip, ip): index
            for index, ip in ping_targets.items()
        }

        for future in as_completed(futures):
            index = futures[future]
            reachable = future.result()

            if not reachable:
                continue

            device = devices[index]
            device["connected"] = True
            device["reachable_by_ping"] = True
            device["presence_source"] = "ping"
            device["source"] = f"{device.get('source', 'history')}+ping"
            device["network"] = "Ping local"
            device["band"] = device.get("band", "")


def attach_presence_metadata(devices, presence_by_mac):
    """Copia fechas y estado persistidos hacia los dispositivos de respuesta."""

    for device in devices:
        mac = normalize_mac(device.get("mac", "") or "")
        presence = presence_by_mac.get(mac)

        if not presence:
            continue

        for field in (
            "first_seen",
            "last_seen",
            "last_checked",
            "last_disconnected",
            "ip",
            "hostname",
            "fabricante",
            "band",
            "network",
        ):
            if presence.get(field) and not device.get(field):
                device[field] = presence[field]

        device["connected"] = bool(presence.get("connected"))


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
            "No se pudo conectar con el router local. "
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


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Servidor HTTP que oculta cortes normales del navegador local."""

    def handle_error(self, request, client_address):
        """Evita tracebacks cuando el browser aborta una conexion ya abierta."""

        error_type, _, _ = sys.exc_info()

        if error_type in (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

        super().handle_error(request, client_address)


class WebHandler(BaseHTTPRequestHandler):
    """Manejador HTTP que sirve el panel y sus rutas JSON."""

    server_version = "GestorWiFiWeb/1.0"

    def auth_session(self):
        """Devuelve la sesion del navegador actual, si existe."""

        if not hasattr(self, "_auth_session"):
            self._auth_session = get_auth_session(self.headers.get("Cookie", ""))

        return self._auth_session

    def ensure_authenticated(self):
        """Protege las rutas API que leen o modifican datos del router."""

        if self.auth_session():
            return True

        self.respond_json({
            "ok": False,
            "auth_required": True,
            "error": "Inicie sesion con las credenciales del router KAON.",
        }, status=401)
        return False

    def crear_cliente_router(self):
        """Crea el cliente KAON con las credenciales de la sesion activa."""

        session = self.auth_session()

        if not session:
            raise RuntimeError("No hay una sesion activa del router.")

        return crear_cliente_router(session)

    def do_GET(self):
        """Despacha solicitudes GET entre API JSON y archivos estaticos."""

        parsed = urlparse(self.path)

        if parsed.path == "/api/auth/status":
            self.handle_auth_status()
            return

        if parsed.path.startswith("/api/") and not self.ensure_authenticated():
            return

        if parsed.path == "/api/devices":
            self.handle_devices(parse_qs(parsed.query))
            return

        if parsed.path == "/api/history":
            self.handle_history(parse_qs(parsed.query))
            return

        if parsed.path == "/api/blocked":
            self.handle_blocked()
            return

        if parsed.path == "/api/guest":
            params = parse_qs(parsed.query)
            self.handle_guest_config(params.get("band", ["2.4"])[0])
            return

        if parsed.path == "/api/primary":
            params = parse_qs(parsed.query)
            self.handle_primary_config(params.get("band", ["2.4"])[0])
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
            if parsed.path == "/api/auth/login":
                self.handle_auth_login()
                return

            if parsed.path == "/api/auth/logout":
                self.handle_auth_logout()
                return

            if parsed.path.startswith("/api/") and not self.ensure_authenticated():
                return

            if parsed.path == "/api/devices/alias":
                self.handle_save_alias()
                return

            if parsed.path == "/api/devices/block":
                self.handle_block_device()
                return

            if parsed.path == "/api/devices/unblock":
                self.handle_unblock_device()
                return

            if parsed.path == "/api/devices/forget":
                self.handle_forget_device()
                return

            if parsed.path == "/api/devices/history/clear":
                self.handle_clear_device_history()
                return

            if parsed.path == "/api/guest":
                self.handle_update_guest()
                return

            if parsed.path == "/api/primary":
                self.handle_update_primary()
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
            message = public_error_message(error)

            try:
                record_audit_event(
                    "system",
                    "operation_failed",
                    "Operacion administrativa no completada",
                    subject=parsed.path,
                    detail=message,
                    status="error",
                )
            except Exception:
                pass

            self.respond_json({"ok": False, "error": message}, status=500)

    def handle_auth_status(self):
        """Informa si el navegador ya tiene una sesion local activa."""

        session = self.auth_session()
        self.respond_json({
            "ok": True,
            "authenticated": bool(session),
            "router_url": ROUTER_URL,
            "username": session.get("username", "") if session else "",
        })

    def handle_history(self, params=None):
        """Devuelve la cronologia unificada de presencia y administracion."""

        params = params or {}
        events = list_activity_events(
            limit=params.get("limit", [200])[0],
            category=params.get("category", [""])[0],
            status=params.get("status", [""])[0],
            event=params.get("event", [""])[0],
            query=params.get("query", [""])[0],
        )
        events = without_router_events(events)
        self.respond_json({
            "ok": True,
            "events": events,
            "count": len(events),
        })

    def handle_auth_login(self):
        """Valida credenciales contra el router y abre una sesion local."""

        payload = self.read_json()
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")

        if not username or not password:
            record_audit_event(
                "session",
                "login_failed",
                "Inicio de sesion rechazado",
                subject=username or "Sin usuario",
                detail="Faltan credenciales del router.",
                status="warning",
            )
            self.respond_json({
                "ok": False,
                "auth_error": True,
                "error": "Escriba el usuario y la contrasena del router KAON.",
            }, status=400)
            return

        credentials = {
            "username": username,
            "password": password,
        }

        try:
            router = crear_cliente_router(credentials)
            router.obtener_pagina_acceso()
        except Exception as error:
            response = getattr(error, "response", None)
            router_status = getattr(response, "status_code", None)

            if router_status == 401:
                message = "El usuario y la contrasena no coinciden con el router KAON."
                status = 401
            else:
                message = public_error_message(error)
                status = 502

            record_audit_event(
                "session",
                "login_failed",
                "Inicio de sesion rechazado",
                subject=username,
                detail=message,
                status="error" if status == 502 else "warning",
            )

            self.respond_json({
                "ok": False,
                "auth_error": True,
                "error": message,
            }, status=status)
            return

        token = create_auth_session(username, password)
        self._auth_session = get_auth_session(f"{AUTH_COOKIE_NAME}={token}")
        record_audit_event(
            "session",
            "login_success",
            "Sesion iniciada",
            subject=username,
            detail="Credenciales confirmadas por el router KAON.",
        )
        self.respond_json({
            "ok": True,
            "authenticated": True,
            "router_url": ROUTER_URL,
            "username": username,
            "message": "Credenciales aceptadas por el router KAON.",
        }, headers={"Set-Cookie": _auth_cookie_header(token)})

    def handle_auth_logout(self):
        """Cierra la sesion local sin tocar el router."""

        session = self.auth_session() or {}
        record_audit_event(
            "session",
            "logout",
            "Sesion cerrada",
            subject=session.get("username", "Usuario local"),
            status="info",
        )
        destroy_auth_session(self.headers.get("Cookie", ""))
        self._auth_session = None
        self.respond_json({
            "ok": True,
            "authenticated": False,
            "message": "Sesion cerrada.",
        }, headers={"Set-Cookie": _clear_auth_cookie_header()})

    def handle_devices(self, params=None, scan_results=None):
        """Responde con clientes WiFi y dispositivos detectados por Nmap."""

        probe = _query_bool(params, "probe", True)
        aliases = get_aliases()
        scanned_devices = without_router(list_scanned_devices())
        known_devices = without_router(list_presence_devices())
        clients = []
        blocked_macs = set()
        clients_available = False
        blocked_macs_available = False
        limit_result = {"applied": [], "errors": []}
        warnings = []

        try:
            with ROUTER_OPERATION_LOCK:
                router = self.crear_cliente_router()

                try:
                    clients = without_router(
                        router.listar_clientes_todas_las_bandas()
                    )
                    clients_available = True
                except Exception as error:
                    warnings.append(
                        "Clientes WiFi: " + public_error_message(error)
                    )

                try:
                    blocked_macs = set(
                        router.obtener_macs_bloqueadas_todas_las_bandas()
                    )
                    blocked_macs_available = True
                except Exception as error:
                    warnings.append(
                        "Usuarios bloqueados: " + public_error_message(error)
                    )

                if clients_available and blocked_macs_available:
                    limit_result = enforce_wifi_client_limits(
                        router,
                        clients,
                        blocked_macs,
                    )

                    if limit_result["errors"]:
                        warnings.append(
                            "Limite de usuarios: " + "; ".join(limit_result["errors"])
                        )
        except Exception as error:
            warnings.append(public_error_message(error))

        combined_devices = merge_router_and_scanned_devices(
            clients,
            scanned_devices,
            known_devices,
        )
        combined_devices = without_router(combined_devices)
        apply_connectivity_probe(combined_devices, probe=probe)
        presence_by_mac = record_device_snapshot(combined_devices)
        attach_presence_metadata(combined_devices, presence_by_mac)
        devices = [
            normalize_device(
                device,
                aliases,
                blocked_macs,
                source="router" if clients_available else "database",
            )
            for device in combined_devices
        ]
        history = without_router_events(list_activity_events(limit=50))
        response = {
            "ok": True,
            "source": "router+nmap" if clients_available else "database",
            "router_reachable": clients_available or blocked_macs_available,
            "router_clients_available": clients_available,
            "devices": devices,
            "history": history,
            "blocked_macs": sorted(blocked_macs),
            "blocked_macs_available": blocked_macs_available,
            "router_count": len(clients),
            "scanned_count": len(scanned_devices),
            "active_count": sum(1 for device in devices if device["connected"]),
            "offline_count": sum(1 for device in devices if not device["connected"]),
            "subnet": local_subnet_label(),
            "host_wifi": get_host_wifi_connection(),
            "wifi_limit_actions": limit_result["applied"],
        }

        if warnings:
            response["warning"] = " ".join(dict.fromkeys(warnings))

        if scan_results is not None:
            safe_scan_results = without_router(scan_results)
            scan_devices = merge_router_and_scanned_devices(
                clients if clients_available else [],
                safe_scan_results,
                [],
            )
            scan_devices = without_router(scan_devices)

            for device in scan_devices:
                device["connected"] = True

            response["scan_devices"] = [
                normalize_device(
                    device,
                    aliases,
                    blocked_macs,
                    source=device.get("source", "database"),
                )
                for device in scan_devices
            ]
            response["scan_count"] = len(scan_devices)

        self.respond_json(response)

    def handle_blocked(self):
        """Responde con la lista de MAC actualmente bloqueadas en el router."""

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()
            blocked_macs = router.obtener_macs_bloqueadas_todas_las_bandas()

        self.respond_json({
            "ok": True,
            "blocked_macs": blocked_macs,
        })

    def handle_guest_config(self, band):
        """Responde con la configuracion de red de invitados de una banda."""

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()
            guest = router.obtener_config_red_invitados(band=band)
            attach_managed_client_limit(guest, "guest", band)

        self.respond_json({
            "ok": True,
            "band": band,
            "guest": guest,
        })

    def handle_primary_config(self, band):
        """Responde con la configuracion de red primaria de una banda."""

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()
            primary = router.obtener_config_red_primaria(band=band)
            attach_managed_client_limit(primary, "primary", band)

        self.respond_json({
            "ok": True,
            "band": band,
            "primary": primary,
        })

    def handle_scanned_devices(self):
        """Responde con dispositivos historicos guardados por el escaner Nmap."""

        aliases = get_aliases()
        devices = [
            normalize_device(device, aliases, source="database")
            for device in without_router(list_scanned_devices())
        ]
        self.respond_json({"ok": True, "devices": devices})

    def handle_parental_sites(self, mac=""):
        """Responde con perfiles de control parental y su estado actual."""

        mac = normalize_mac(mac or "")

        if mac and not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        try:
            with ROUTER_OPERATION_LOCK:
                router = self.crear_cliente_router()
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
        record_audit_event(
            "device",
            "alias_updated",
            "Nombre de dispositivo actualizado",
            subject=alias["alias"],
            detail=f"Equipo {mac}",
            metadata={"mac": mac},
        )
        self.respond_json({"ok": True, "device": alias})

    def handle_block_device(self):
        """Bloquea una MAC desde la API y confirma el estado si hay timeout."""

        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        if is_protected_router_mac(mac):
            record_audit_event(
                "access",
                "user_block_failed",
                "Bloqueo de usuario rechazado",
                subject=audit_device_subject(mac),
                detail="El equipo corresponde al router protegido.",
                status="warning",
                metadata={"mac": mac},
            )
            self.respond_json({
                "ok": False,
                "error": "El router esta protegido y no se puede bloquear.",
            }, status=400)
            return

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()
            result = router.bloquear_mac_todas_las_redes(mac)
        warning = "; ".join(dict.fromkeys(
            public_error_message(error)
            for error in result["errors"]
        ))

        if not result["all_interfaces_confirmed"]:
            record_audit_event(
                "access",
                "user_block_failed",
                "Bloqueo de usuario no confirmado",
                subject=audit_device_subject(mac),
                detail=warning or "El router no confirmo todas las interfaces WiFi.",
                status="error",
                metadata={"mac": mac, "expected_count": result.get("expected_count", 0)},
            )
            self.respond_json({
                "ok": False,
                "error": (
                    "El bloqueo no se confirmo en todas las interfaces WiFi activas. "
                    "No se actualizo el estado del dispositivo. "
                    f"Detalle: {warning or 'El router no devolvio una confirmacion completa.'}"
                ),
                "mac": mac,
                "interfaces": result.get("interfaces", []),
                "expected_count": result.get("expected_count", 0),
            }, status=502)
            return

        interface_label = (
            "interfaz WiFi" if result["success_count"] == 1 else "interfaces WiFi"
        )
        message = f"Usuario bloqueado en {result['success_count']} {interface_label}."

        if warning:
            message += " Algunas interfaces no pudieron confirmarse."

        record_audit_event(
            "access",
            "user_blocked",
            "Usuario bloqueado",
            subject=audit_device_subject(mac),
            detail=message,
            status="warning" if warning else "success",
            metadata={"mac": mac, "interfaces": result.get("interfaces", [])},
        )

        self.respond_json({
            "ok": True,
            "message": message,
            "warning": warning,
            "mac": mac,
            "interfaces": result.get("interfaces", []),
        })

    def handle_unblock_device(self):
        """Desbloquea una MAC desde la API y confirma el estado si hay timeout."""

        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()
            result = router.desbloquear_mac_todas_las_redes(mac)
        warning = "; ".join(dict.fromkeys(
            public_error_message(error)
            for error in result["errors"]
        ))

        if not result["all_interfaces_confirmed"]:
            record_audit_event(
                "access",
                "user_unblock_failed",
                "Desbloqueo de usuario no confirmado",
                subject=audit_device_subject(mac),
                detail=warning or "El router no confirmo todas las interfaces WiFi.",
                status="error",
                metadata={"mac": mac, "expected_count": result.get("expected_count", 0)},
            )
            self.respond_json({
                "ok": False,
                "error": (
                    "El desbloqueo no se confirmo en todas las interfaces WiFi activas. "
                    "No se actualizo el estado del dispositivo. "
                    f"Detalle: {warning or 'El router no devolvio una confirmacion completa.'}"
                ),
                "mac": mac,
                "interfaces": result.get("interfaces", []),
                "expected_count": result.get("expected_count", 0),
            }, status=502)
            return

        interface_label = (
            "interfaz WiFi" if result["success_count"] == 1 else "interfaces WiFi"
        )
        message = f"Usuario desbloqueado de {result['success_count']} {interface_label}."

        if warning:
            message += " Algunas interfaces no pudieron confirmarse."

        record_audit_event(
            "access",
            "user_unblocked",
            "Usuario desbloqueado",
            subject=audit_device_subject(mac),
            detail=message,
            status="warning" if warning else "success",
            metadata={"mac": mac, "interfaces": result.get("interfaces", [])},
        )

        self.respond_json({
            "ok": True,
            "message": message,
            "warning": warning,
            "mac": mac,
            "interfaces": result.get("interfaces", []),
        })

    def handle_forget_device(self):
        """Borra un dispositivo y su historial local desde el panel."""

        payload = self.read_json()
        mac = normalize_mac(payload.get("mac", ""))

        if not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        subject = audit_device_subject(mac)
        forget_device(mac)
        record_audit_event(
            "device",
            "device_forgotten",
            "Dispositivo olvidado",
            subject=subject,
            detail=f"Se eliminaron los datos locales de {mac}.",
            status="info",
            metadata={"mac": mac},
        )
        self.respond_json({
            "ok": True,
            "message": "Dispositivo eliminado del historial local.",
            "mac": mac,
        })

    def handle_clear_device_history(self):
        """Borra eventos de presencia y operaciones administrativas."""

        clear_activity_events()
        self.respond_json({"ok": True, "message": "Historial de actividad borrado."})

    def handle_parental_action(self, block):
        """Bloquea o desbloquea un perfil de sitios en control parental."""

        payload = self.read_json()
        profile = get_site_blocking_profile(payload.get("profile_id", ""))
        mac = normalize_mac(payload.get("mac", "") or "")
        hardening = bool(payload.get("hardening"))

        if mac and not is_valid_mac(mac):
            self.respond_json({"ok": False, "error": "La MAC no es valida."}, status=400)
            return

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()

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

        record_audit_event(
            "parental",
            "site_blocked" if block else "site_unblocked",
            "Sitio o servicio bloqueado" if block else "Sitio o servicio desbloqueado",
            subject=profile["name"],
            detail=(
                f"Alcance: {mac or 'todos los dispositivos'}. "
                f"Refuerzo: {'activo' if hardening else 'inactivo'}."
            ),
            status="warning" if warning else "success",
            metadata={
                "profile_id": profile["id"],
                "mac": mac,
                "hardening": hardening,
            },
        )

        self.respond_json(response)

    def handle_update_guest(self):
        """Activa o desactiva la red de invitados con los datos recibidos."""

        payload = self.read_json()
        band = payload.get("band", "2.4")
        enabled = bool(payload.get("enabled"))
        limit_requested = "max_clients" in payload
        previous_limit = get_wifi_client_limit("guest", band)

        with ROUTER_OPERATION_LOCK:
            router = self.crear_cliente_router()
            previous = router.obtener_config_red_invitados(band=band)
            router.configurar_red_invitados(
                ssid=payload.get("ssid") or None,
                password=payload.get("password") or None,
                ocultar_ssid=bool(payload.get("hidden")) if "hidden" in payload else None,
                habilitada=enabled,
                band=band,
            )
            message = "Red de invitados activada." if enabled else "Red de invitados desactivada."

        if limit_requested:
            set_wifi_client_limit("guest", band, payload.get("max_clients"))
            message += " Limite de usuarios guardado."

        record_audit_event(
            "wifi",
            "guest_updated",
            "Red de invitados actualizada",
            subject=f"{band} GHz",
            detail=wifi_change_detail(payload, previous, previous_limit),
            metadata={"band": band, "interface": "guest"},
        )

        self.respond_json({"ok": True, "message": message})

    def handle_update_primary(self):
        """Actualiza SSID, clave WPA y visibilidad de una red primaria."""

        payload = self.read_json()
        band = payload.get("band", "2.4")
        updates = {}
        limit_requested = "max_clients" in payload
        previous_limit = get_wifi_client_limit("primary", band)
        previous = {}

        if "ssid" in payload:
            updates["ssid"] = payload.get("ssid")

        if payload.get("password"):
            updates["password"] = payload.get("password")

        if "hidden" in payload:
            updates["ocultar_ssid"] = bool(payload.get("hidden"))

        if "enabled" in payload:
            updates["habilitada"] = bool(payload.get("enabled"))

        if not updates and not limit_requested:
            self.respond_json({
                "ok": False,
                "error": "No se recibieron cambios para aplicar.",
            }, status=400)
            return

        if updates:
            with ROUTER_OPERATION_LOCK:
                router = self.crear_cliente_router()
                previous = router.obtener_config_red_primaria(band=band)
                router.configurar_red_primaria(band=band, **updates)

        message = f"Red primaria {band} GHz actualizada."

        if limit_requested:
            set_wifi_client_limit("primary", band, payload.get("max_clients"))
            message += " Limite de usuarios guardado."

        record_audit_event(
            "wifi",
            "primary_updated",
            "Red primaria actualizada",
            subject=f"{band} GHz",
            detail=wifi_change_detail(payload, previous, previous_limit),
            metadata={"band": band, "interface": "primary"},
        )

        self.respond_json({
            "ok": True,
            "message": message,
        })

    def handle_scan(self):
        """Ejecuta Nmap sobre la subred local y devuelve dispositivos guardados."""

        subnet = get_subnet()

        if subnet is None:
            record_audit_event(
                "scan",
                "scan_failed",
                "Escaneo de red no iniciado",
                detail="No se pudo detectar la subred local.",
                status="warning",
            )
            self.respond_json({
                "ok": False,
                "error": "No se pudo detectar la subred local.",
            }, status=400)
            return

        db = EscanerRedDB(str(DATABASE_PATH))

        try:
            scan_results = db.escanear_red(str(subnet))
        finally:
            db.close()

        scan_count = len(without_router(scan_results))
        record_audit_event(
            "scan",
            "network_scanned",
            "Escaneo de red completado",
            subject=str(subnet),
            detail=f"{scan_count} equipos detectados.",
            metadata={"subnet": str(subnet), "device_count": scan_count},
        )

        self.handle_devices(scan_results=scan_results)

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

    def respond_json(self, payload, status=200, headers=None):
        """Serializa una respuesta JSON con cabeceras sin cache."""

        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")

        for header, value in (headers or {}).items():
            self.send_header(header, value)

        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Redirige el log HTTP al formato simple del servidor local."""

        print(f"[web] {self.address_string()} - {format % args}")


def main():
    """Configura argumentos CLI y ejecuta el servidor HTTP local."""

    parser = argparse.ArgumentParser(description="Servidor web local del Gestor WiFi KAON")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8001, type=int)
    args = parser.parse_args()

    server = QuietThreadingHTTPServer((args.host, args.port), WebHandler)
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
