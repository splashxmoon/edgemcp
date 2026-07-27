"""Device discovery from the operating system's ARP/neighbour table.

Reading the ARP table requires no privileges on any supported platform: it is
the same information ``arp -a`` shows to any user. To make that table useful we
first "warm" it with a sweep of harmless UDP datagrams, which causes the kernel
to resolve each local address to a MAC.
"""

from __future__ import annotations

import asyncio
import re
import socket
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..models import is_multicast_mac, normalise_mac
from ..netinfo import run_command

#: Port 9 is the standard "discard" service. Nothing listens on it, so the
#: datagram is dropped by the target's IP stack after ARP resolution -- which is
#: the only side effect we actually want.
_SWEEP_PORT = 9

_ARP_LINE_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"          # IPv4 address
    # Anything up to the MAC, on the same line. This must tolerate digits:
    # `ip neigh` prints "192.168.1.1 dev wlan0 lladdr aa:bb:..." and a
    # digit-free separator silently matched nothing on any numbered interface.
    r"[^\n]*?"
    # Octets may be printed unpadded: macOS renders 0x00 as "0", not "00".
    r"(?P<mac>(?:[0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})"
)


@dataclass
class ArpEntry:
    """One IP-to-MAC binding as reported by the OS."""

    ip: str
    mac: str


def _read_proc_net_arp() -> List[ArpEntry]:
    """Read /proc/net/arp directly on Linux, avoiding a subprocess."""
    entries: List[ArpEntry] = []
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()[1:]  # skip the header row
    except OSError:
        return entries

    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        mac = normalise_mac(fields[3])
        # 00:00:00:00:00:00 means the entry is incomplete (no reply yet).
        if mac and mac != "00:00:00:00:00:00":
            entries.append(ArpEntry(ip=fields[0], mac=mac))
    return entries


def _parse_arp_output(output: str) -> List[ArpEntry]:
    """Extract IP/MAC pairs from ``arp -a`` output on any platform.

    The three platforms format this differently ("192.168.1.1 ether aa:bb..." vs
    "192.168.1.1  aa-bb-..  dynamic" vs "? (192.168.1.1) at aa:bb:.."), so we
    match on the shape of the data rather than on column positions.
    """
    entries: List[ArpEntry] = []
    seen: set[str] = set()

    for line in output.splitlines():
        match = _ARP_LINE_RE.search(line)
        if not match:
            continue
        mac = normalise_mac(match.group("mac"))
        ip = match.group("ip")
        if not mac or mac == "00:00:00:00:00:00" or is_multicast_mac(mac):
            continue
        if ip in seen:
            continue
        seen.add(ip)
        entries.append(ArpEntry(ip=ip, mac=mac))

    return entries


def read_arp_table() -> List[ArpEntry]:
    """Return the current ARP table. Never raises."""
    if sys.platform.startswith("linux"):
        entries = _read_proc_net_arp()
        if entries:
            return entries
        # Older/containerised systems may not expose /proc/net/arp.
        output = run_command(["ip", "neigh", "show"]) or run_command(["arp", "-a", "-n"])
        return _parse_arp_output(output)

    if sys.platform == "win32":
        return _parse_arp_output(run_command(["arp", "-a"]))

    return _parse_arp_output(run_command(["arp", "-an"]))


async def warm_arp_cache(hosts: List[str], settle_seconds: float = 1.5) -> None:
    """Nudge the kernel into ARP-resolving every host in the subnet.

    Sends one empty UDP datagram per host to the discard port. This is local
    LAN traffic only -- roughly 254 packets of 42 bytes on a typical /24, which
    is far less than a single web page load -- and it needs no privileges.
    """
    if not hosts:
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        for host in hosts:
            try:
                sock.sendto(b"", (host, _SWEEP_PORT))
            except OSError:
                # Unreachable hosts and buffer-full conditions are expected;
                # the point is to trigger ARP, not to deliver anything.
                continue
            # Yield periodically so we do not monopolise the event loop or
            # overrun the socket send buffer on large subnets.
            await asyncio.sleep(0)
    finally:
        sock.close()

    # The ARP replies arrive asynchronously; give the kernel time to record them.
    await asyncio.sleep(settle_seconds)


def resolve_hostname(ip: str, timeout: float = 0.4) -> Optional[str]:
    """Reverse-lookup a hostname using whatever the OS resolver knows.

    On a home network this is answered by the router or by mDNS, both local.
    """
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror, socket.gaierror):
        return None
    finally:
        socket.setdefaulttimeout(original)

    # Strip the mDNS suffix so "printer.local" displays as "printer".
    if name.endswith(".local"):
        name = name[: -len(".local")]
    return name or None


async def discover_via_arp(
    hosts: List[str],
    warm: bool = True,
    settle_seconds: float = 1.5,
) -> Dict[str, str]:
    """Discover devices on the LAN, returning a mapping of IP to MAC."""
    if warm:
        await warm_arp_cache(hosts, settle_seconds=settle_seconds)

    # read_arp_table shells out on most platforms, so keep it off the event loop.
    entries = await asyncio.to_thread(read_arp_table)

    allowed = set(hosts) if hosts else None
    return {
        entry.ip: entry.mac
        for entry in entries
        if allowed is None or entry.ip in allowed
    }
