"""Local machine security and configuration checks.

Checks the machine running the scan for:
- Wi-Fi network encryption (e.g., connected to an open network?)
- DNS configuration (e.g., what DNS servers are in use)
- Local port exposure (e.g., listening ports on 0.0.0.0)
"""

from __future__ import annotations

import asyncio
import os
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LocalSecurityReport:
    wifi_secure: Optional[bool] = None
    wifi_ssid: Optional[str] = None
    wifi_auth_type: Optional[str] = None
    dns_servers: List[str] = None
    listening_ports: List[Dict[str, Any]] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.dns_servers is None:
            self.dns_servers = []
        if self.listening_ports is None:
            self.listening_ports = []
        if self.warnings is None:
            self.warnings = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "wifi_secure": self.wifi_secure,
            "wifi_ssid": self.wifi_ssid,
            "wifi_auth_type": self.wifi_auth_type,
            "dns_servers": self.dns_servers,
            "listening_ports": self.listening_ports,
            "warnings": self.warnings,
        }


async def _check_wifi_windows() -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    """Check Wi-Fi security on Windows using netsh."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "netsh", "wlan", "show", "interfaces",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        stdout, _ = await proc.communicate()
        text = stdout.decode("utf-8", errors="ignore")
        
        ssid = None
        auth = None
        
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("SSID") and not line.startswith("BSSID"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ssid = parts[1].strip()
            elif line.startswith("Authentication"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    auth = parts[1].strip()
                    
        if ssid and auth:
            secure = auth.lower() not in ("open", "none")
            return secure, ssid, auth
            
    except Exception:
        pass
        
    return None, None, None


async def _check_wifi_mac() -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    """Check Wi-Fi security on macOS."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "-I",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        text = stdout.decode("utf-8", errors="ignore")
        
        ssid = None
        auth = None
        
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
            elif line.startswith("link auth:"):
                auth = line.split(":", 1)[1].strip()
                
        if ssid and auth:
            secure = auth.lower() not in ("none", "open")
            return secure, ssid, auth
    except Exception:
        pass
        
    return None, None, None


async def get_wifi_security() -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    sys = platform.system().lower()
    if sys == "windows":
        return await _check_wifi_windows()
    elif sys == "darwin":
        return await _check_wifi_mac()
    # Linux wifi check is complex due to nmcli/iw, omitting for now
    return None, None, None


async def get_dns_servers() -> List[str]:
    """Get configured DNS servers using platform-specific commands."""
    servers = set()
    sys = platform.system().lower()
    
    try:
        if sys == "windows":
            proc = await asyncio.create_subprocess_exec(
                "ipconfig", "/all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            stdout, _ = await proc.communicate()
            text = stdout.decode("utf-8", errors="ignore")
            
            in_dns = False
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("DNS Servers"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if ip and ":" not in ip: # prefer IPv4
                            servers.add(ip)
                        in_dns = True
                elif in_dns:
                    if ":" in line and not line.startswith(re.search(r"^[0-9a-fA-F]", line) and ":" in line):
                        # another property started
                        in_dns = False
                    else:
                        ip = line.strip()
                        if ip and ":" not in ip: # prefer IPv4
                            servers.add(ip)
        else:
            # macOS / Linux
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            if ":" not in ip: # prefer IPv4
                                servers.add(ip)
    except Exception:
        pass
        
    return list(servers)


async def get_listening_ports() -> List[Dict[str, Any]]:
    """Get listening ports exposed to the local network (0.0.0.0)."""
    ports = []
    sys = platform.system().lower()
    
    try:
        if sys == "windows":
            proc = await asyncio.create_subprocess_exec(
                "netstat", "-an", "-p", "tcp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            stdout, _ = await proc.communicate()
            text = stdout.decode("utf-8", errors="ignore")
            
            for line in text.splitlines():
                #  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
                if "LISTENING" in line and "0.0.0.0:" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[1]
                        if local_addr.startswith("0.0.0.0:"):
                            port_str = local_addr.split(":")[1]
                            if port_str.isdigit():
                                ports.append({
                                    "protocol": "tcp",
                                    "port": int(port_str),
                                    "address": "0.0.0.0"
                                })
        else:
            # macOS / Linux
            proc = await asyncio.create_subprocess_exec(
                "netstat", "-an",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            text = stdout.decode("utf-8", errors="ignore")
            
            for line in text.splitlines():
                if "LISTEN" in line and "tcp" in line.lower():
                    parts = line.split()
                    if len(parts) >= 4:
                        local_addr = parts[3]
                        if local_addr.startswith("0.0.0.0:") or local_addr.startswith("*.") or local_addr.endswith(".*"):
                            try:
                                port_str = local_addr.split(".")[-1]
                                if ":" in local_addr:
                                    port_str = local_addr.split(":")[-1]
                                if port_str.isdigit():
                                    ports.append({
                                        "protocol": "tcp",
                                        "port": int(port_str),
                                        "address": "0.0.0.0"
                                    })
                            except Exception:
                                pass
    except Exception:
        pass
        
    return ports


async def run_local_checks() -> LocalSecurityReport:
    """Run all local security and configuration checks."""
    report = LocalSecurityReport()
    
    try:
        report.wifi_secure, report.wifi_ssid, report.wifi_auth_type = await get_wifi_security()
        report.dns_servers = await get_dns_servers()
        report.listening_ports = await get_listening_ports()
        
    except Exception as exc:
        report.warnings.append(f"Local checks failed: {exc}")
        
    return report
