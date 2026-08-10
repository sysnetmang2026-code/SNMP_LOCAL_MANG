"""Persistencia auxiliar de dispositivos, alias y presencia.

El escaner Nmap guarda dispositivos detectados en la tabla `dispositivos`. Este
modulo agrega tablas complementarias para que el panel pueda asignar nombres
amigables, recordar el ultimo estado de conexion y mostrar un historial de
entradas, salidas y cambios de red sin alterar los datos detectados por Nmap.
Todas las operaciones se apoyan en SQLite y usan la ruta centralizada en
`config.DATABASE_PATH`.
"""

import json
import sqlite3
from datetime import datetime, timezone

from config import DATABASE_PATH
from validators import normalize_mac


WIFI_CLIENT_LIMIT_MAX = 20
WIFI_LIMIT_KINDS = {"primary", "guest"}
WIFI_LIMIT_BANDS = {"2.4", "5"}
AUDIT_EVENT_STATUSES = {"success", "info", "warning", "error"}
AUDIT_SENSITIVE_PARTS = ("password", "passwd", "secret", "token", "credential")


def _connect():
    """Abre una conexion SQLite hacia la base local del proyecto."""

    return sqlite3.connect(DATABASE_PATH)


def _utc_now():
    """Devuelve la fecha actual en UTC como texto ISO 8601."""

    return datetime.now(timezone.utc).isoformat()


def ensure_device_tables():
    """Crea las tablas auxiliares de dispositivos si todavia no existen."""

    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_aliases (
                mac TEXT PRIMARY KEY,
                alias TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_presence (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                fabricante TEXT,
                band TEXT,
                network TEXT,
                connected INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_checked TEXT NOT NULL,
                last_disconnected TEXT,
                source TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_presence_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT NOT NULL,
                event TEXT NOT NULL,
                ip TEXT,
                hostname TEXT,
                network TEXT,
                band TEXT,
                detail TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wifi_client_limits (
                interface_kind TEXT NOT NULL,
                band TEXT NOT NULL,
                limit_value INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (interface_kind, band)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                event TEXT NOT NULL,
                status TEXT NOT NULL,
                title TEXT NOT NULL,
                subject TEXT,
                detail TEXT,
                metadata_json TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
            ON audit_events(created_at DESC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_events_category
            ON audit_events(category)
        """)
        conn.commit()


def ensure_alias_table():
    """Crea la tabla de alias si todavia no existe."""

    ensure_device_tables()


def get_aliases():
    """Obtiene los alias registrados como un diccionario indexado por MAC."""

    ensure_device_tables()

    with _connect() as conn:
        rows = conn.execute("SELECT mac, alias FROM device_aliases").fetchall()

    return {mac: alias for mac, alias in rows}


def save_alias(mac, alias):
    """Guarda o actualiza el alias visible asociado a una direccion MAC.

    Args:
        mac: Direccion MAC del dispositivo. Se normaliza a mayusculas.
        alias: Nombre visible elegido por el usuario.

    Raises:
        ValueError: Si el alias esta vacio o supera 48 caracteres.

    Returns:
        Diccionario con la MAC normalizada y el alias persistido.
    """

    mac = normalize_mac(mac)
    alias = alias.strip()

    if not alias:
        raise ValueError("El nombre no puede estar vacio.")

    if len(alias) > 48:
        raise ValueError("El nombre debe tener 48 caracteres o menos.")

    ensure_device_tables()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO device_aliases (mac, alias, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                alias = excluded.alias,
                updated_at = excluded.updated_at
            """,
            (mac, alias, _utc_now()),
        )
        conn.commit()

    return {"mac": mac, "alias": alias}


def list_presence_devices():
    """Lista dispositivos conocidos por el historial de presencia."""

    ensure_device_tables()

    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT mac, ip, hostname, fabricante, band, network, connected,
                   first_seen, last_seen, last_checked, last_disconnected,
                   source
            FROM device_presence
            ORDER BY connected DESC, last_seen DESC
        """).fetchall()

    devices_by_mac = {}

    for row in rows:
        device = dict(row)
        mac = normalize_mac(device.get("mac", "") or "")

        if not mac:
            continue

        device["mac"] = mac

        if mac not in devices_by_mac:
            devices_by_mac[mac] = device
            continue

        current = devices_by_mac[mac]

        if (
            (not current.get("hostname") or current.get("hostname") == "Desconocido")
            and device.get("hostname")
            and device.get("hostname") != "Desconocido"
        ):
            current["hostname"] = device["hostname"]

        if not current.get("fabricante") and device.get("fabricante"):
            current["fabricante"] = device["fabricante"]

    return list(devices_by_mac.values())


def get_presence_by_mac():
    """Devuelve el estado de presencia indexado por direccion MAC."""

    return {
        normalize_mac(row["mac"]): row
        for row in list_presence_devices()
        if row.get("mac")
    }


def _event_detail(event, previous_network, current_network):
    """Construye una descripcion corta para cambios de estado."""

    if event == "moved":
        return f"Cambio de red: {previous_network or 'sin red'} -> {current_network or 'sin red'}"

    return ""


def _insert_presence_event(conn, mac, event, device, detail, now):
    """Registra un evento historico de conexion para una MAC."""

    conn.execute(
        """
        INSERT INTO device_presence_events
            (mac, event, ip, hostname, network, band, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            mac,
            event,
            device.get("ip", ""),
            device.get("hostname", ""),
            device.get("network", ""),
            device.get("band", ""),
            detail,
            now,
        ),
    )


def record_device_snapshot(devices):
    """Actualiza presencia e historial a partir de una lectura del panel.

    Args:
        devices: Lista de diccionarios normalizados parcialmente. Cada elemento
            debe incluir `mac` y puede incluir `connected`, `ip`, `network` y
            otros metadatos detectados por router, Nmap o ping.

    Returns:
        Diccionario de presencia actualizado, indexado por MAC.
    """

    ensure_device_tables()
    now = _utc_now()

    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        existing_rows = conn.execute("""
            SELECT mac, ip, hostname, fabricante, band, network, connected,
                   first_seen, last_seen, last_checked, last_disconnected,
                   source
            FROM device_presence
        """).fetchall()
        existing_by_mac = {
            normalize_mac(row["mac"]): dict(row)
            for row in existing_rows
            if row["mac"]
        }
        current_macs = set()

        for raw_device in devices:
            mac = normalize_mac(raw_device.get("mac", "") or "")

            if not mac:
                continue

            current_macs.add(mac)
            connected = 1 if raw_device.get("connected") else 0
            previous = existing_by_mac.get(mac)
            was_connected = bool(previous and previous.get("connected"))
            previous_network = previous.get("network", "") if previous else ""
            current_network = raw_device.get("network", "") or ""
            event = ""

            if connected and not was_connected:
                event = "connected"
            elif not connected and was_connected:
                event = "disconnected"
            elif connected and previous_network != current_network:
                event = "moved"

            first_seen = previous.get("first_seen") if previous else now
            last_seen = now if connected else (previous.get("last_seen") if previous else now)
            last_disconnected = (
                now
                if event == "disconnected"
                else (previous.get("last_disconnected") if previous else None)
            )

            conn.execute(
                """
                INSERT INTO device_presence (
                    mac, ip, hostname, fabricante, band, network, connected,
                    first_seen, last_seen, last_checked, last_disconnected,
                    source
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = excluded.hostname,
                    fabricante = excluded.fabricante,
                    band = excluded.band,
                    network = excluded.network,
                    connected = excluded.connected,
                    last_seen = excluded.last_seen,
                    last_checked = excluded.last_checked,
                    last_disconnected = excluded.last_disconnected,
                    source = excluded.source
                """,
                (
                    mac,
                    raw_device.get("ip", ""),
                    raw_device.get("hostname", ""),
                    raw_device.get("fabricante", ""),
                    raw_device.get("band", ""),
                    current_network,
                    connected,
                    first_seen,
                    last_seen,
                    now,
                    last_disconnected,
                    raw_device.get("source", "history"),
                ),
            )

            if event:
                detail = _event_detail(event, previous_network, current_network)
                _insert_presence_event(conn, mac, event, raw_device, detail, now)

        for mac, previous in existing_by_mac.items():
            if not previous.get("connected") or mac in current_macs:
                continue

            device = {
                "ip": previous.get("ip", ""),
                "hostname": previous.get("hostname", ""),
                "network": previous.get("network", ""),
                "band": previous.get("band", ""),
            }
            conn.execute(
                """
                UPDATE device_presence
                SET connected = 0,
                    last_checked = ?,
                    last_disconnected = ?
                WHERE mac = ?
                """,
                (now, now, mac),
            )
            _insert_presence_event(conn, mac, "disconnected", device, "", now)

        conn.commit()

    return get_presence_by_mac()


def list_presence_events(limit=30):
    """Lista eventos recientes de conexion con alias cuando exista."""

    ensure_device_tables()
    limit = max(1, min(int(limit or 30), 200))

    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT e.id, e.mac, e.event, e.ip, e.hostname, e.network, e.band,
                   e.detail, e.created_at, a.alias
            FROM device_presence_events e
            LEFT JOIN device_aliases a ON e.mac = a.mac
            ORDER BY e.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def clear_presence_events():
    """Borra el historial de eventos sin olvidar dispositivos conocidos."""

    ensure_device_tables()

    with _connect() as conn:
        conn.execute("DELETE FROM device_presence_events")
        conn.commit()


def _redact_audit_metadata(value):
    """Elimina secretos de metadatos antes de serializarlos en la bitacora."""

    if isinstance(value, dict):
        safe = {}

        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            safe[key_text] = (
                "[redacted]"
                if any(part in lowered for part in AUDIT_SENSITIVE_PARTS)
                else _redact_audit_metadata(item)
            )

        return safe

    if isinstance(value, (list, tuple)):
        return [_redact_audit_metadata(item) for item in value]

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


def record_audit_event(
    category,
    event,
    title,
    subject="",
    detail="",
    status="success",
    metadata=None,
):
    """Registra una operacion del panel sin persistir datos sensibles."""

    category = str(category or "system").strip().lower()[:32]
    event = str(event or "activity").strip().lower()[:64]
    status = str(status or "info").strip().lower()
    title = str(title or "Actividad del panel").strip()[:160]
    subject = str(subject or "").strip()[:180]
    detail = str(detail or "").strip()[:1000]

    if status not in AUDIT_EVENT_STATUSES:
        status = "info"

    safe_metadata = _redact_audit_metadata(metadata or {})
    created_at = _utc_now()
    ensure_device_tables()

    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO audit_events
                (category, event, status, title, subject, detail,
                 metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                category,
                event,
                status,
                title,
                subject,
                detail,
                json.dumps(safe_metadata, ensure_ascii=True, sort_keys=True),
                created_at,
            ),
        )
        conn.commit()

    return {
        "id": f"audit:{cursor.lastrowid}",
        "source": "audit",
        "category": category,
        "event": event,
        "status": status,
        "title": title,
        "subject": subject,
        "detail": detail,
        "metadata": safe_metadata,
        "created_at": created_at,
    }


def _presence_activity_event(item):
    """Normaliza un evento de presencia al contrato general de actividad."""

    event = item.get("event", "activity")
    status = "success" if event == "connected" else "info"
    subject = item.get("alias") or item.get("hostname") or item.get("mac") or "Dispositivo"

    return {
        **item,
        "id": f"presence:{item.get('id', '')}",
        "source": "presence",
        "category": "device",
        "status": status,
        "title": "",
        "subject": subject,
        "metadata": {},
    }


def list_activity_events(limit=200, category="", status="", event="", query=""):
    """Combina presencia y auditoria en una cronologia filtrable."""

    ensure_device_tables()
    limit = max(1, min(int(limit or 200), 500))
    category = str(category or "").strip().lower()
    status = str(status or "").strip().lower()
    event = str(event or "").strip().lower()
    query = str(query or "").strip().lower()
    items = []

    if category in ("", "all", "device"):
        for row in list_presence_events(limit=limit):
            item = _presence_activity_event(row)

            if status and status != "all" and item["status"] != status:
                continue

            if event and event != "all" and item["event"] != event:
                continue

            items.append(item)

    if category != "presence":
        clauses = []
        values = []

        if category and category != "all":
            clauses.append("category = ?")
            values.append(category)

        if status and status != "all":
            clauses.append("status = ?")
            values.append(status)

        if event and event != "all":
            clauses.append("event = ?")
            values.append(event)

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT id, category, event, status, title, subject, detail,
                       metadata_json, created_at
                FROM audit_events
                {where_clause}
                ORDER BY id DESC
                LIMIT ?
                """,
                (*values, limit),
            ).fetchall()

        for row in rows:
            item = dict(row)
            raw_metadata = item.pop("metadata_json", "")

            try:
                item["metadata"] = json.loads(raw_metadata or "{}")
            except json.JSONDecodeError:
                item["metadata"] = {}

            item["id"] = f"audit:{item['id']}"
            item["source"] = "audit"
            items.append(item)

    if query:
        searchable_fields = (
            "category",
            "event",
            "title",
            "subject",
            "detail",
            "alias",
            "hostname",
            "mac",
            "network",
            "band",
        )
        items = [
            item
            for item in items
            if query in " ".join(str(item.get(field, "")) for field in searchable_fields).lower()
        ]

    items.sort(
        key=lambda item: (item.get("created_at", ""), str(item.get("id", ""))),
        reverse=True,
    )
    return items[:limit]


def clear_activity_events():
    """Borra eventos de presencia y auditoria sin olvidar dispositivos."""

    ensure_device_tables()

    with _connect() as conn:
        conn.execute("DELETE FROM device_presence_events")
        conn.execute("DELETE FROM audit_events")
        conn.commit()


def forget_device(mac):
    """Elimina un dispositivo de las tablas locales administradas por el panel."""

    mac = normalize_mac(mac)
    ensure_device_tables()

    with _connect() as conn:
        conn.execute("DELETE FROM device_aliases WHERE mac = ?", (mac,))
        conn.execute("DELETE FROM device_presence WHERE mac = ?", (mac,))
        conn.execute("DELETE FROM device_presence_events WHERE mac = ?", (mac,))

        try:
            conn.execute("DELETE FROM dispositivos WHERE UPPER(mac) = ?", (mac,))
        except sqlite3.OperationalError:
            pass

        conn.commit()


def normalize_wifi_limit_kind(kind):
    """Normaliza el tipo de interfaz WiFi usado por los limites locales."""

    value = str(kind or "").strip().lower()

    if value not in WIFI_LIMIT_KINDS:
        raise ValueError("La interfaz WiFi debe ser primary o guest.")

    return value


def normalize_wifi_limit_band(band):
    """Normaliza la banda WiFi usada por los limites locales."""

    value = str(band or "").strip().lower().replace("ghz", "").replace(" ", "")

    if value in ("2", "24", "2.4"):
        return "2.4"

    if value in ("5", "5.0"):
        return "5"

    raise ValueError("La banda WiFi debe ser 2.4 o 5 GHz.")


def validate_wifi_client_limit(limit_value):
    """Valida un limite local de clientes WiFi."""

    try:
        limit = int(limit_value)
    except (TypeError, ValueError) as error:
        raise ValueError("El limite de usuarios debe ser un numero.") from error

    if limit < 0 or limit > WIFI_CLIENT_LIMIT_MAX:
        raise ValueError(
            f"El limite de usuarios debe estar entre 0 y {WIFI_CLIENT_LIMIT_MAX}."
        )

    return limit


def set_wifi_client_limit(kind, band, limit_value):
    """Guarda o elimina el limite local de usuarios para una interfaz WiFi."""

    kind = normalize_wifi_limit_kind(kind)
    band = normalize_wifi_limit_band(band)
    ensure_device_tables()

    with _connect() as conn:
        if limit_value in (None, ""):
            conn.execute(
                """
                DELETE FROM wifi_client_limits
                WHERE interface_kind = ? AND band = ?
                """,
                (kind, band),
            )
            conn.commit()
            return None

        limit = validate_wifi_client_limit(limit_value)
        conn.execute(
            """
            INSERT INTO wifi_client_limits
                (interface_kind, band, limit_value, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(interface_kind, band) DO UPDATE SET
                limit_value = excluded.limit_value,
                updated_at = excluded.updated_at
            """,
            (kind, band, limit, _utc_now()),
        )
        conn.commit()

    return limit


def get_wifi_client_limit(kind, band):
    """Devuelve el limite local de usuarios para una interfaz, si existe."""

    kind = normalize_wifi_limit_kind(kind)
    band = normalize_wifi_limit_band(band)
    ensure_device_tables()

    with _connect() as conn:
        row = conn.execute(
            """
            SELECT limit_value
            FROM wifi_client_limits
            WHERE interface_kind = ? AND band = ?
            """,
            (kind, band),
        ).fetchone()

    return int(row[0]) if row else None


def get_wifi_client_limits():
    """Devuelve todos los limites locales indexados por `(tipo, banda)`."""

    ensure_device_tables()

    with _connect() as conn:
        rows = conn.execute("""
            SELECT interface_kind, band, limit_value
            FROM wifi_client_limits
        """).fetchall()

    limits = {}

    for kind, band, limit_value in rows:
        limits[(kind, band)] = int(limit_value)

    return limits


def list_scanned_devices():
    """Lista dispositivos detectados por Nmap junto con sus alias opcionales.

    Si la tabla historica `dispositivos` aun no existe, se devuelve una lista
    vacia para que el panel web pueda seguir operando en modo degradado.
    """

    ensure_device_tables()

    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("""
                SELECT d.ip, d.mac, d.hostname, d.fabricante, a.alias
                FROM dispositivos d
                LEFT JOIN device_aliases a ON UPPER(d.mac) = a.mac
                ORDER BY d.id DESC
            """).fetchall()
        except sqlite3.OperationalError:
            return []

    return [dict(row) for row in rows]
