"""SSDP (Simple Service Discovery Protocol) device discovery.

Sends an M-SEARCH query to the SSDP multicast group and listens for responses.
Devices respond with their Server headers and ST (Search Target) headers, which
can provide strong hints about device type and manufacturer.
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Dict, List, Set, Tuple

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2

SSDP_QUERY = (
    f"M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    f"MAN: \"ssdp:discover\"\r\n"
    f"MX: {SSDP_MX}\r\n"
    f"ST: ssdp:all\r\n"
    f"\r\n"
).encode("utf-8")


class SsdpHost:
    """Evidence collected from one host via SSDP."""
    def __init__(self, ip: str):
        self.ip: str = ip
        self.server_headers: Set[str] = set()
        self.st_headers: Set[str] = set()


class SsdpProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.hosts: Dict[str, SsdpHost] = {}
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport):
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        ip = addr[0]
        if ip not in self.hosts:
            self.hosts[ip] = SsdpHost(ip)
        
        host = self.hosts[ip]
        text = data.decode("utf-8", errors="ignore")
        
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            
            # Match header: value
            parts = line.split(":", 1)
            if len(parts) == 2:
                header = parts[0].strip().lower()
                value = parts[1].strip()
                if header == "server":
                    host.server_headers.add(value)
                elif header == "st":
                    host.st_headers.add(value)


async def discover_via_ssdp(duration: float = 2.5) -> Tuple[Dict[str, SsdpHost], List[str]]:
    """Broadcast an SSDP M-SEARCH and collect responses for `duration` seconds.
    
    Returns:
        A tuple of (map of IP to SsdpHost, list of warnings).
    """
    warnings: List[str] = []
    loop = asyncio.get_running_loop()

    # We need a UDP socket bound to an ephemeral port
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Restrict multicast TTL to local network
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

    try:
        sock.bind(("", 0))
    except Exception as exc:
        sock.close()
        warnings.append(f"Could not bind SSDP UDP socket: {exc}")
        return {}, warnings

    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: SsdpProtocol(),
            sock=sock,
        )
    except Exception as exc:
        sock.close()
        warnings.append(f"Could not start SSDP protocol: {exc}")
        return {}, warnings

    try:
        # Send query
        transport.sendto(SSDP_QUERY, (SSDP_ADDR, SSDP_PORT))
        
        # Wait for responses
        await asyncio.sleep(duration)
        
    except Exception as exc:
        warnings.append(f"Error during SSDP discovery: {exc}")
    finally:
        transport.close()

    return protocol.hosts, warnings
