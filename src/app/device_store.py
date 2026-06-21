import sqlite3
from datetime import datetime, timezone

from config import DATABASE_PATH
from validators import normalize_mac


def _connect():
    return sqlite3.connect(DATABASE_PATH)


def ensure_alias_table():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_aliases (
                mac TEXT PRIMARY KEY,
                alias TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()


def get_aliases():
    ensure_alias_table()

    with _connect() as conn:
        rows = conn.execute("SELECT mac, alias FROM device_aliases").fetchall()

    return {mac: alias for mac, alias in rows}


def save_alias(mac, alias):
    mac = normalize_mac(mac)
    alias = alias.strip()

    if not alias:
        raise ValueError("El nombre no puede estar vacio.")

    if len(alias) > 48:
        raise ValueError("El nombre debe tener 48 caracteres o menos.")

    ensure_alias_table()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO device_aliases (mac, alias, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                alias = excluded.alias,
                updated_at = excluded.updated_at
            """,
            (mac, alias, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    return {"mac": mac, "alias": alias}


def list_scanned_devices():
    ensure_alias_table()

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
