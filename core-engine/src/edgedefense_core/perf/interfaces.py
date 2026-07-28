"""Per-adapter traffic counters, link speed and error rates.

Answers "is my network card actually healthy, and what is moving through it
right now" without contacting anything. All figures come from counters the
operating system already maintains.

Counters are cumulative since boot, which is not what a person means when they
ask how fast their network is going. :func:`sample_interfaces` therefore takes
two readings a second or so apart and reports the delta as a live rate.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ._proc import run, run_powershell

#: Adapters that exist for virtualisation or tunnelling rather than for
#: carrying the user's traffic. Reporting them as "your network" is noise.
_VIRTUAL_HINTS = (
    "loopback",
    "vethernet",
    "vmware",
    "virtualbox",
    "hyper-v",
    "docker",
    "wsl",
    "tailscale",
    "zerotier",
    "tap-windows",
    "teredo",
    "isatap",
    "bluetooth",
)


@dataclass
class InterfaceStats:
    """One network adapter, as the operating system sees it."""

    name: str
    description: Optional[str] = None
    is_up: bool = False
    mac: Optional[str] = None
    mtu: Optional[int] = None
    link_speed_mbps: Optional[float] = None
    bytes_sent: Optional[int] = None
    bytes_recv: Optional[int] = None
    packets_sent: Optional[int] = None
    packets_recv: Optional[int] = None
    errors_in: Optional[int] = None
    errors_out: Optional[int] = None
    drops_in: Optional[int] = None
    drops_out: Optional[int] = None
    is_virtual: bool = False
    #: Live throughput, present only on the output of :func:`sample_interfaces`.
    send_rate_bps: Optional[float] = None
    recv_rate_bps: Optional[float] = None

    def error_rate(self) -> Optional[float]:
        """Errored + dropped packets as a fraction of all packets seen.

        Returns ``None`` when the platform does not expose enough counters to
        compute it honestly, rather than quietly treating a missing counter as
        zero and reporting a perfect link.
        """
        total = (self.packets_recv or 0) + (self.packets_sent or 0)
        if not total:
            return None
        bad = sum(
            value or 0
            for value in (self.errors_in, self.errors_out, self.drops_in, self.drops_out)
        )
        if all(
            value is None
            for value in (self.errors_in, self.errors_out, self.drops_in, self.drops_out)
        ):
            return None
        return bad / total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "is_up": self.is_up,
            "mac": self.mac,
            "mtu": self.mtu,
            "link_speed_mbps": self.link_speed_mbps,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "errors_in": self.errors_in,
            "errors_out": self.errors_out,
            "drops_in": self.drops_in,
            "drops_out": self.drops_out,
            "error_rate": self.error_rate(),
            "is_virtual": self.is_virtual,
            "send_rate_bps": self.send_rate_bps,
            "recv_rate_bps": self.recv_rate_bps,
        }


@dataclass
class InterfaceReport:
    """Every adapter on the machine, plus how the sample was taken."""

    interfaces: List[InterfaceStats] = field(default_factory=list)
    sample_seconds: Optional[float] = None
    warnings: List[str] = field(default_factory=list)

    def active(self) -> List[InterfaceStats]:
        """Adapters that are up, real, and have actually carried traffic."""
        return [
            iface
            for iface in self.interfaces
            if iface.is_up and not iface.is_virtual and (iface.bytes_recv or iface.bytes_sent)
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_seconds": self.sample_seconds,
            "interfaces": [iface.to_dict() for iface in self.interfaces],
            "warnings": self.warnings,
        }


def looks_virtual(name: str, description: Optional[str] = None) -> bool:
    """True for loopback, VPN and hypervisor adapters."""
    haystack = f"{name} {description or ''}".lower()
    if name in ("lo", "lo0"):
        return True
    return any(hint in haystack for hint in _VIRTUAL_HINTS)


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------


def _read_sysfs(interface: str, attribute: str) -> Optional[str]:
    """Read one /sys/class/net attribute, tolerating the many that error."""
    try:
        with open(f"/sys/class/net/{interface}/{attribute}", "r") as handle:
            return handle.read().strip()
    except OSError:
        # Virtual and wireless adapters legitimately refuse `speed`.
        return None


def _collect_linux() -> List[InterfaceStats]:
    """Parse /proc/net/dev, which is the authoritative counter source here."""
    try:
        with open("/proc/net/dev", "r") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return []

    interfaces: List[InterfaceStats] = []
    for line in lines:
        if ":" not in line:
            continue  # The two header rows.
        name, _, rest = line.partition(":")
        name = name.strip()
        fields = rest.split()
        if len(fields) < 16:
            continue

        def value(index: int) -> Optional[int]:
            try:
                return int(fields[index])
            except (ValueError, IndexError):
                return None

        speed_raw = _read_sysfs(name, "speed")
        mtu_raw = _read_sysfs(name, "mtu")
        try:
            speed = float(speed_raw) if speed_raw is not None else None
        except ValueError:
            speed = None
        # A down adapter reports -1; presenting that as a link speed is worse
        # than presenting nothing.
        if speed is not None and speed <= 0:
            speed = None

        interfaces.append(
            InterfaceStats(
                name=name,
                description=None,
                is_up=(_read_sysfs(name, "operstate") or "") in ("up", "unknown"),
                mac=_read_sysfs(name, "address"),
                mtu=int(mtu_raw) if (mtu_raw or "").isdigit() else None,
                link_speed_mbps=speed,
                bytes_recv=value(0),
                packets_recv=value(1),
                errors_in=value(2),
                drops_in=value(3),
                bytes_sent=value(8),
                packets_sent=value(9),
                errors_out=value(10),
                drops_out=value(11),
                is_virtual=looks_virtual(name),
            )
        )
    return interfaces


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------


async def _collect_macos() -> List[InterfaceStats]:
    """Parse ``netstat -ibn``, mapping columns by header rather than position.

    The column set differs between macOS releases (``Drop`` comes and goes), so
    a fixed index would silently read the wrong number on some machines.
    """
    output = await run(["netstat", "-ibn"])
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines:
        return []

    header = lines[0].split()
    index = {column: position for position, column in enumerate(header)}

    def column(fields: List[str], *names: str) -> Optional[int]:
        for column_name in names:
            position = index.get(column_name)
            if position is not None and position < len(fields):
                try:
                    return int(fields[position])
                except ValueError:
                    return None
        return None

    interfaces: List[InterfaceStats] = []
    seen: set = set()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < len(header) - 1:
            continue
        name = fields[0]
        # Each adapter appears once per address family; the <Link#n> row is the
        # one carrying the hardware counters.
        if "<Link#" not in line or name in seen:
            continue
        seen.add(name)

        mtu = column(fields, "Mtu")
        mac = None
        address_position = index.get("Address")
        if address_position is not None and address_position < len(fields):
            candidate = fields[address_position]
            if re.fullmatch(r"(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}", candidate):
                mac = candidate

        interfaces.append(
            InterfaceStats(
                name=name,
                mtu=mtu,
                mac=mac,
                is_up=True,  # netstat -ibn lists configured adapters only.
                bytes_recv=column(fields, "Ibytes"),
                packets_recv=column(fields, "Ipkts"),
                errors_in=column(fields, "Ierrs"),
                drops_in=column(fields, "Drop", "Idrop"),
                bytes_sent=column(fields, "Obytes"),
                packets_sent=column(fields, "Opkts"),
                errors_out=column(fields, "Oerrs"),
                is_virtual=looks_virtual(name),
            )
        )
    return interfaces


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------

#: One PowerShell round trip for both halves of the picture: Get-NetAdapter has
#: the link properties, Get-NetAdapterStatistics has the counters, and starting
#: PowerShell twice costs more than the query itself.
_WINDOWS_SCRIPT = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$a=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,"
    "Speed,MacAddress,MtuSize);"
    "$s=@(Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes,"
    "ReceivedUnicastPackets,SentUnicastPackets,ReceivedPacketErrors,"
    "OutboundPacketErrors,ReceivedDiscardedPackets,OutboundDiscardedPackets);"
    "ConvertTo-Json -Compress -Depth 3 @{adapters=$a;stats=$s}"
)


def _as_list(payload: Any) -> List[Dict[str, Any]]:
    """Normalise PowerShell's habit of collapsing a one-element array."""
    if payload is None:
        return []
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


async def _collect_windows() -> List[InterfaceStats]:
    """Query Get-NetAdapter / Get-NetAdapterStatistics and join them by name."""
    raw = await run_powershell(_WINDOWS_SCRIPT)
    if not raw.strip():
        return []
    try:
        payload = json.loads(raw)
    except (ValueError, TypeError):
        return []

    stats_by_name = {
        str(entry.get("Name")): entry for entry in _as_list(payload.get("stats"))
    }

    interfaces: List[InterfaceStats] = []
    for adapter in _as_list(payload.get("adapters")):
        name = str(adapter.get("Name") or "")
        if not name:
            continue
        description = adapter.get("InterfaceDescription")
        counters = stats_by_name.get(name, {})

        speed_bps = adapter.get("Speed")
        try:
            speed_mbps = float(speed_bps) / 1e6 if speed_bps else None
        except (TypeError, ValueError):
            speed_mbps = None

        def counter(key: str) -> Optional[int]:
            value = counters.get(key)
            try:
                return int(value) if value is not None else None
            except (TypeError, ValueError):
                return None

        mac = adapter.get("MacAddress")
        interfaces.append(
            InterfaceStats(
                name=name,
                description=str(description) if description else None,
                is_up=str(adapter.get("Status") or "").lower() == "up",
                mac=str(mac).replace("-", ":").lower() if mac else None,
                mtu=int(adapter["MtuSize"]) if str(adapter.get("MtuSize") or "").isdigit() else None,
                link_speed_mbps=speed_mbps,
                bytes_recv=counter("ReceivedBytes"),
                bytes_sent=counter("SentBytes"),
                packets_recv=counter("ReceivedUnicastPackets"),
                packets_sent=counter("SentUnicastPackets"),
                errors_in=counter("ReceivedPacketErrors"),
                errors_out=counter("OutboundPacketErrors"),
                drops_in=counter("ReceivedDiscardedPackets"),
                drops_out=counter("OutboundDiscardedPackets"),
                is_virtual=looks_virtual(name, str(description) if description else None),
            )
        )
    return interfaces


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


async def collect_interfaces() -> InterfaceReport:
    """Read every adapter's current counters. One snapshot, no waiting."""
    report = InterfaceReport()
    try:
        if sys.platform == "win32":
            report.interfaces = await _collect_windows()
        elif sys.platform == "darwin":
            report.interfaces = await _collect_macos()
        else:
            report.interfaces = await asyncio.to_thread(_collect_linux)
    except Exception as exc:  # noqa: BLE001 - a stats read must never take the server down
        report.warnings.append(f"Could not read adapter statistics: {exc}")
        return report

    if not report.interfaces:
        report.warnings.append(
            "No adapter statistics were available. This usually means the "
            "operating system tool that reports them is missing or restricted."
        )
    return report


async def sample_interfaces(seconds: float = 2.0) -> InterfaceReport:
    """Measure live throughput by diffing two counter readings.

    Args:
        seconds: how long to wait between readings. Longer is steadier; below
            about a second the numbers are dominated by sampling jitter.

    Returns:
        A report whose ``send_rate_bps`` / ``recv_rate_bps`` describe current
        traffic, and whose cumulative counters come from the second reading.
    """
    seconds = max(0.5, min(float(seconds), 30.0))

    first = await collect_interfaces()
    if not first.interfaces:
        return first

    started = asyncio.get_running_loop().time()
    await asyncio.sleep(seconds)
    second = await collect_interfaces()
    # The sleep is the floor, not the total: collecting the second reading is
    # itself slow on Windows, and charging that time to the rate would understate
    # throughput by a third.
    elapsed = asyncio.get_running_loop().time() - started

    baseline = {iface.name: iface for iface in first.interfaces}
    for iface in second.interfaces:
        previous = baseline.get(iface.name)
        if previous is None or elapsed <= 0:
            continue
        iface.send_rate_bps = _rate(previous.bytes_sent, iface.bytes_sent, elapsed)
        iface.recv_rate_bps = _rate(previous.bytes_recv, iface.bytes_recv, elapsed)

    second.sample_seconds = round(elapsed, 2)
    return second


def _rate(before: Optional[int], after: Optional[int], elapsed: float) -> Optional[float]:
    """Bits per second between two byte counters, or None if unusable."""
    if before is None or after is None:
        return None
    delta = after - before
    if delta < 0:
        return None  # Counter wrapped or the adapter was reset mid-sample.
    return (delta * 8) / elapsed
