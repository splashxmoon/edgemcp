"""NetBIOS Name Service (NBNS) device discovery.

Sends a Node Status Request to UDP port 137 to ask a host for its NetBIOS name.
This is particularly useful for identifying Windows machines, older NAS devices,
and some printers that don't respond to mDNS.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Dict, List, Optional, Tuple

NBNS_PORT = 137

# A generic Node Status Request packet for NetBIOS
# Transaction ID: 0x8228 (arbitrary)
# Flags: 0x0000 (Standard query)
# Questions: 1, Answers: 0, Authority: 0, Additional: 0
# Query Name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (which decodes to "*")
# Query Type: 0x0021 (Node Status)
# Query Class: 0x0001 (IN)
NBNS_QUERY = (
    b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
    b"\x41\x41\x41\x00\x00\x21\x00\x01"
)

def _parse_nbns_response(data: bytes) -> Optional[str]:
    """Parse a NetBIOS Node Status Response to extract the primary hostname."""
    if len(data) < 58:  # Minimum size for a valid node status response
        return None
        
    # Check Transaction ID to match our query
    if data[0:2] != b"\x82\x28":
        return None
        
    # Check flags for response
    if not (data[2] & 0x80):
        return None

    # Number of names in the node status response
    try:
        num_names = data[56]
        offset = 57
        
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name_bytes = data[offset:offset+15]
            type_byte = data[offset+15]
            flags = struct.unpack(">H", data[offset+16:offset+18])[0]
            
            # Type 0x00 is Workstation/Machine name. 
            # We want the unique name (Group bit not set in flags, which is bit 15)
            is_group = bool(flags & 0x8000)
            if type_byte == 0x00 and not is_group:
                name = name_bytes.decode("ascii", errors="ignore").strip()
                if name:
                    return name
            
            offset += 18
    except Exception:
        pass
        
    return None


async def resolve_netbios_name(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Send an NBNS Node Status Request to a specific IP."""
    loop = asyncio.get_running_loop()
    
    class NbnsProtocol(asyncio.DatagramProtocol):
        def __init__(self):
            self.transport: asyncio.DatagramTransport | None = None
            self.result: asyncio.Future[Optional[str]] = loop.create_future()
            
        def connection_made(self, transport: asyncio.BaseTransport):
            self.transport = transport # type: ignore
            self.transport.sendto(NBNS_QUERY, (ip, NBNS_PORT))
            
        def datagram_received(self, data: bytes, addr: Tuple[str, int]):
            if addr[0] == ip:
                name = _parse_nbns_response(data)
                if not self.result.done():
                    self.result.set_result(name)
                    
        def error_received(self, exc: Exception):
            if not self.result.done():
                self.result.set_result(None)

    transport = None
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: NbnsProtocol(),
            remote_addr=(ip, NBNS_PORT)
        )
        return await asyncio.wait_for(protocol.result, timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    except Exception:
        return None
    finally:
        if transport:
            transport.close()


async def scan_netbios(ips: List[str], timeout: float = 0.5) -> Dict[str, str]:
    """Resolve NetBIOS names for a list of IPs concurrently."""
    async def _resolve(ip: str) -> Tuple[str, Optional[str]]:
        name = await resolve_netbios_name(ip, timeout=timeout)
        return ip, name
        
    results = await asyncio.gather(*(_resolve(ip) for ip in ips))
    return {ip: name for ip, name in results if name}
