"""Local-only persistence.

Everything written here stays on the machine that ran the scan. There is no
sync, no upload, and no telemetry -- the database is a plain SQLite file the
user can inspect or delete at any time, and :func:`purge_all` is provided so
that deleting it is a first-class operation rather than a manual chore.

Persistence exists for exactly two reasons:
    * "first seen" timestamps, so a genuinely new device can be recognised
    * letting follow-up questions work without re-scanning
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Bump when the schema changes in a way that needs migration.
SCHEMA_VERSION = 1

#: Keep enough history to answer "what changed?" without growing unbounded.
_MAX_SCANS_RETAINED = 20


def default_data_dir() -> Path:
    """Return the per-user data directory, following platform convention."""
    override = os.environ.get("EDGEDEFENSE_DATA_DIR")
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        return Path(base) / "edgedefense"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "edgedefense"

    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "edgedefense"


def utc_now() -> str:
    """Current time as an ISO-8601 UTC string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    """A thin SQLite wrapper. Safe to construct repeatedly."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self.data_dir = Path(data_dir) if data_dir else default_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "edgedefense.sqlite3"
        self._init_schema()

    # -- connection helpers ------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id  TEXT PRIMARY KEY,
                    mac        TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen  TEXT NOT NULL,
                    last_ip    TEXT,
                    last_label TEXT
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    finished_at TEXT NOT NULL,
                    payload     TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns introduced after the first release.

        Done additively so an existing database keeps its first-seen history
        rather than being recreated.
        """
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
        for column in ("mdns_services", "hostname"):
            if column not in existing:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {column} TEXT")

    # -- settings ----------------------------------------------------------

    def get_setting(self, key: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # -- devices -----------------------------------------------------------

    def load_device_memory(self) -> Dict[str, Dict[str, Any]]:
        """Return accumulated per-device evidence from previous scans.

        mDNS is lossy: a device that answered last time may stay silent during
        this scan's listening window, which would otherwise make its identified
        type flip between runs. Devices do not change what they are, so unioning
        the evidence across scans makes identification stable and lets it
        improve over time rather than resetting on every scan.
        """
        memory: Dict[str, Dict[str, Any]] = {}
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    "SELECT device_id, mdns_services, hostname FROM devices"
                ).fetchall()
            except sqlite3.OperationalError:
                return memory

        for row in rows:
            services: List[str] = []
            if row["mdns_services"]:
                try:
                    loaded = json.loads(row["mdns_services"])
                    if isinstance(loaded, list):
                        services = [str(s) for s in loaded]
                except json.JSONDecodeError:
                    services = []
            memory[row["device_id"]] = {
                "mdns_services": services,
                "hostname": row["hostname"],
            }
        return memory

    def record_devices(self, devices: List[Any]) -> Dict[str, str]:
        """Upsert devices and return each one's original first-seen timestamp.

        A device's ``first_seen`` is never overwritten, which is what makes
        "this device appeared today" a statement we can actually stand behind.
        """
        now = utc_now()
        first_seen_map: Dict[str, str] = {}

        with self._connect() as conn:
            for device in devices:
                row = conn.execute(
                    "SELECT first_seen FROM devices WHERE device_id = ?",
                    (device.device_id,),
                ).fetchone()
                first_seen = row["first_seen"] if row else now
                first_seen_map[device.device_id] = first_seen

                conn.execute(
                    """
                    INSERT INTO devices(
                        device_id, mac, first_seen, last_seen, last_ip, last_label,
                        mdns_services, hostname
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                        last_seen     = excluded.last_seen,
                        last_ip       = excluded.last_ip,
                        last_label    = excluded.last_label,
                        mac           = COALESCE(excluded.mac, devices.mac),
                        mdns_services = excluded.mdns_services,
                        hostname      = COALESCE(excluded.hostname, devices.hostname)
                    """,
                    (
                        device.device_id,
                        device.mac,
                        first_seen,
                        now,
                        device.ip,
                        device.label(),
                        json.dumps(sorted(device.mdns_services)),
                        device.hostname,
                    ),
                )

        return first_seen_map

    def known_device_count(self) -> int:
        """How many distinct devices have ever been seen on this network."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM devices").fetchone()
        return int(row["n"]) if row else 0

    # -- scans -------------------------------------------------------------

    def save_scan(self, payload: Dict[str, Any]) -> None:
        """Persist a scan result and prune old ones."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scans(finished_at, payload) VALUES(?, ?)",
                (payload.get("finished_at") or utc_now(), json.dumps(payload)),
            )
            conn.execute(
                """
                DELETE FROM scans WHERE id NOT IN (
                    SELECT id FROM scans ORDER BY id DESC LIMIT ?
                )
                """,
                (_MAX_SCANS_RETAINED,),
            )

    def load_latest_scan(self) -> Optional[Dict[str, Any]]:
        """Return the most recent scan payload, or None if never scanned."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            return None

    # -- housekeeping ------------------------------------------------------

    def purge_all(self) -> str:
        """Delete every stored record. Returns the path that was cleared."""
        with self._connect() as conn:
            conn.executescript(
                "DELETE FROM devices; DELETE FROM scans; DELETE FROM settings;"
            )
        self._init_schema()
        return str(self.db_path)

    def describe(self) -> Dict[str, Any]:
        """Where the data lives and how much of it there is."""
        with self._connect() as conn:
            devices = conn.execute("SELECT COUNT(*) AS n FROM devices").fetchone()["n"]
            scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
        return {
            "database_path": str(self.db_path),
            "devices_known": int(devices),
            "scans_stored": int(scans),
            "transmitted_anywhere": False,
        }
