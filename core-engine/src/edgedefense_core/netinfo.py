"""Local network facts: our own address, the subnet, and the default gateway.

Everything here is read-only, needs no elevated privileges, and never contacts
anything outside the local machine or LAN.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

#: Suppress the console window that would otherwise flash on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0


def run_command(args: List[str], timeout: float = 8.0) -> str:
    """Run a local command and return stdout, or "" on any failure.

    Output is decoded leniently because ``arp``/``ipconfig`` emit the console
    codepage on Windows, which is not always UTF-8.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.decode(errors="replace")


@dataclass
class LocalNetwork:
    """What we know about the network this machine sits on."""

    local_ip: Optional[str]
    netmask: Optional[str]
    gateway: Optional[str]
    cidr: Optional[str]

    def hosts(self, max_hosts: int = 512) -> List[str]:
        """Every host address in the subnet, capped for sanity.

        The cap keeps a mis-detected /16 from turning a "quick" scan into a
        65k-host sweep.
        """
        if not self.cidr:
            return []
        try:
            network = ipaddress.ip_network(self.cidr, strict=False)
        except ValueError:
            return []
        if network.num_addresses > max_hosts * 4:
            return []
        return [str(h) for h in network.hosts()][:max_hosts]


def get_local_ip() -> Optional[str]:
    """Determine the IP of the interface holding the default route.

    Uses a connected UDP socket to a TEST-NET-1 address (RFC 5737). UDP connect
    only sets the socket's peer for routing purposes, so no packet is ever sent
    and nothing leaves the machine.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _netmask_windows(local_ip: str) -> Optional[str]:
    """Find the subnet mask listed alongside ``local_ip`` in ipconfig output."""
    output = run_command(["ipconfig"])
    # Adapter blocks are separated by blank lines; find the one with our IP.
    for block in re.split(r"\n\s*\n", output):
        if local_ip not in block:
            continue
        match = re.search(r"(?:Subnet Mask|Subnetzmaske)[ .]*:\s*([0-9.]+)", block)
        if match:
            return match.group(1)
        # Fall back to any dotted quad that looks like a mask.
        for candidate in re.findall(r"\b(255\.[0-9.]+)\b", block):
            return candidate
    return None


def _netmask_linux(local_ip: str) -> Optional[str]:
    """Read the prefix length from ``ip -o -4 addr`` and convert to a mask."""
    output = run_command(["ip", "-o", "-4", "addr", "show"])
    match = re.search(rf"\b{re.escape(local_ip)}/(\d{{1,2}})\b", output)
    if match:
        prefix = int(match.group(1))
        return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)
    return None


def _netmask_macos(local_ip: str) -> Optional[str]:
    """Parse ``ifconfig`` output, where masks appear as hex (0xffffff00)."""
    output = run_command(["ifconfig"])
    match = re.search(
        rf"inet\s+{re.escape(local_ip)}\s+netmask\s+(0x[0-9a-fA-F]{{8}}|[0-9.]+)", output
    )
    if not match:
        return None
    raw = match.group(1)
    if raw.startswith("0x"):
        return str(ipaddress.IPv4Address(int(raw, 16)))
    return raw


def get_netmask(local_ip: str) -> Optional[str]:
    """Platform-dispatching subnet mask lookup."""
    try:
        if sys.platform == "win32":
            return _netmask_windows(local_ip)
        if sys.platform == "darwin":
            return _netmask_macos(local_ip)
        return _netmask_linux(local_ip)
    except (ValueError, OSError):
        return None


def get_gateway() -> Optional[str]:
    """Find the default gateway, which is almost always the home router."""
    try:
        if sys.platform == "win32":
            output = run_command(["ipconfig"])
            matches = re.findall(
                r"(?:Default Gateway|Standardgateway)[ .]*:\s*([0-9]+(?:\.[0-9]+){3})",
                output,
            )
            return matches[0] if matches else None

        if sys.platform == "darwin":
            output = run_command(["route", "-n", "get", "default"])
            match = re.search(r"gateway:\s*([0-9]+(?:\.[0-9]+){3})", output)
            return match.group(1) if match else None

        output = run_command(["ip", "route", "show", "default"])
        match = re.search(r"default via ([0-9]+(?:\.[0-9]+){3})", output)
        return match.group(1) if match else None
    except (ValueError, OSError):
        return None


def describe_local_network() -> LocalNetwork:
    """Gather everything the scanner needs to know about where it is running."""
    local_ip = get_local_ip()
    netmask: Optional[str] = None
    cidr: Optional[str] = None

    if local_ip:
        netmask = get_netmask(local_ip)
        try:
            # A /24 fallback matches the overwhelming majority of home networks
            # and keeps the sweep bounded when mask detection fails.
            interface = ipaddress.ip_interface(f"{local_ip}/{netmask or '255.255.255.0'}")
            cidr = str(interface.network)
        except ValueError:
            cidr = None

    return LocalNetwork(
        local_ip=local_ip,
        netmask=netmask,
        gateway=get_gateway(),
        cidr=cidr,
    )


def is_private_ip(ip: str) -> bool:
    """True for RFC1918 / link-local addresses, i.e. addresses on this LAN."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local
