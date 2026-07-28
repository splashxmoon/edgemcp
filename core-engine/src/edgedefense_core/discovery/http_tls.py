"""HTTP and TLS certificate discovery.

Extracts the HTML <title> from HTTP services and the Common Name (CN) from
TLS certificates. These often contain exact product names or brands that
general port-scanning misses.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple


class HttpTlsHost:
    def __init__(self, ip: str):
        self.ip = ip
        self.titles: List[str] = []
        self.tls_cns: List[str] = []


async def _extract_http_title(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """Fetch the root path and extract the <title> tag if present."""
    reader = None
    writer = None
    try:
        # Use asyncio.wait_for around open_connection to enforce timeout on the connect phase
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        request = f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode('ascii')
        writer.write(request)
        await writer.drain()
        
        # Enforce timeout on the read phase
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        text = data.decode("utf-8", errors="ignore")
        
        # Simple regex to grab the title
        match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            # Clean up newlines in title
            title = re.sub(r"\s+", " ", title)
            if title:
                return title
    except Exception:
        pass
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    return None


async def _extract_tls_cn(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """Connect via TLS and extract the Common Name from the certificate."""
    loop = asyncio.get_running_loop()
    
    # Create an unverified context so we can read self-signed certs
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    def _do_connect() -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    return None
                
                # 'subject' is a tuple of tuples: ((('commonName', 'Example'),), ...)
                subject = cert.get("subject", ())
                for rdn in subject:
                    for k, v in rdn:
                        if k == "commonName":
                            return v
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return None
        
    # ssl.SSLSocket blocks, so run in a thread
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_connect),
            timeout=timeout + 0.5
        )
    except Exception:
        return None


async def scan_http_tls(
    open_ports_map: Dict[str, List[int]], 
    timeout: float = 1.0
) -> Dict[str, HttpTlsHost]:
    """Scan open ports for HTTP titles and TLS Common Names."""
    hosts: Dict[str, HttpTlsHost] = {}
    
    # Common ports to check
    http_ports = {80, 8080, 8000, 8081}
    tls_ports = {443, 8443, 9443}
    
    tasks: List[asyncio.Task] = []
    
    async def _check(ip: str, port: int, is_tls: bool):
        if ip not in hosts:
            hosts[ip] = HttpTlsHost(ip)
            
        host = hosts[ip]
        if is_tls:
            cn = await _extract_tls_cn(ip, port, timeout)
            if cn and cn not in host.tls_cns:
                host.tls_cns.append(cn)
        else:
            title = await _extract_http_title(ip, port, timeout)
            if title and title not in host.titles:
                host.titles.append(title)
                
    for ip, ports in open_ports_map.items():
        for port in ports:
            if port in http_ports:
                tasks.append(asyncio.create_task(_check(ip, port, is_tls=False)))
            if port in tls_ports:
                tasks.append(asyncio.create_task(_check(ip, port, is_tls=True)))
                # Some TLS endpoints also answer plain HTTP, but typically we just
                # check TLS if it's a known TLS port.
                
    if tasks:
        await asyncio.gather(*tasks)
        
    # Only return hosts that actually found something
    return {
        ip: host for ip, host in hosts.items() 
        if host.titles or host.tls_cns
    }
