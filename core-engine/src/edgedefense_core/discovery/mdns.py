"""Multicast DNS discovery with no third-party dependencies.

Most consumer devices -- printers, TVs, speakers, phones, NAS boxes -- announce
themselves over mDNS, which makes it by far the richest zero-privilege source of
device identity available.

Two details make this work without elevated permissions:

1. We send from an ephemeral port and set the QU ("unicast response requested")
   bit, so responders reply directly to us instead of to multicast. Binding the
   real mDNS port (5353) is what would normally require privileges or conflict
   with an existing responder such as Avahi or Bonjour.
2. We *additionally* try to join the multicast group on 5353 with address reuse
   enabled. When that works we see far more traffic, but a failure is expected
   and non-fatal.
"""

from __future__ import annotations

import asyncio
import random
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

#: Record types we understand. Everything else is skipped.
TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33

#: The DNS-SD meta-query, which asks "what service types exist here?", plus the
#: service types that most reliably identify a consumer device.
SERVICE_QUERIES: Tuple[str, ...] = (
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local",
    "_workstation._tcp.local",
    "_companion-link._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
    "_pdl-datastream._tcp.local",
    "_printer._tcp.local",
    "_scanner._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_nfs._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_http._tcp.local",
    "_https._tcp.local",
    "_hap._tcp.local",
    "_homekit._tcp.local",
    "_matter._tcp.local",
    "_matterc._udp.local",
    "_hue._tcp.local",
    "_nanoleafapi._tcp.local",
    "_amzn-wplay._tcp.local",
    "_androidtvremote2._tcp.local",
    "_roku-rcp._tcp.local",
    "_plexmediasvr._tcp.local",
    "_rfb._tcp.local",
    "_esphomelib._tcp.local",
    "_home-assistant._tcp.local",
)

#: TXT keys worth keeping: they usually name the exact hardware model.
INTERESTING_TXT_KEYS = ("model", "md", "am", "ty", "usb_mdl", "product", "fn", "device")

#: Extracts the service type from a full instance name. Instance labels are
#: free-form and routinely contain dots and colons (Amazon's Whisperplay names
#: are a good example), so splitting on the first dot mangles them. Anchoring on
#: the "_service._proto.local" suffix is reliable regardless of the prefix.
_SERVICE_TYPE_RE = re.compile(r"(_[^.]+\._(?:tcp|udp)\.local)$", re.IGNORECASE)


@dataclass
class MdnsHost:
    """Everything mDNS told us about a single IP address."""

    ip: str
    hostname: Optional[str] = None
    services: Set[str] = field(default_factory=set)
    txt_hints: Dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Minimal DNS wire-format handling
# --------------------------------------------------------------------------


def _encode_name(name: str) -> bytes:
    """Encode a dotted name into DNS length-prefixed label format."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("utf-8")[:63]
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def build_query(names: Tuple[str, ...], unicast_response: bool = True) -> bytes:
    """Build one mDNS query packet asking for PTR records for ``names``.

    Setting the top bit of the class field is the QU bit, which asks responders
    to answer us directly rather than to the multicast group.
    """
    # ID 0 is conventional for mDNS, but a random ID is also accepted and helps
    # us ignore stray packets when we are bound to an ephemeral port.
    transaction_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", transaction_id, 0x0000, len(names), 0, 0, 0)

    qclass = 0x8001 if unicast_response else 0x0001  # QU bit | IN
    body = b"".join(_encode_name(n) + struct.pack("!HH", TYPE_PTR, qclass) for n in names)
    return header + body


def _read_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a possibly-compressed DNS name.

    Returns the name and the offset just past it. Compression pointers are
    followed but never advance the returned offset, per RFC 1035.
    """
    labels: List[str] = []
    jumped = False
    original_offset = offset
    hops = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            if not jumped:
                original_offset = offset
            break

        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            hops += 1
            if hops > 32:  # malformed/hostile packet with a pointer loop
                break
            continue

        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, (original_offset if jumped else offset)


def _parse_txt(payload: bytes) -> Dict[str, str]:
    """Parse a TXT record's length-prefixed key=value strings."""
    result: Dict[str, str] = {}
    index = 0
    while index < len(payload):
        length = payload[index]
        index += 1
        chunk = payload[index : index + length]
        index += length
        if b"=" not in chunk:
            continue
        key, _, value = chunk.partition(b"=")
        result[key.decode("utf-8", errors="replace").lower()] = value.decode(
            "utf-8", errors="replace"
        )
    return result


@dataclass
class _Records:
    """Raw records accumulated across every response packet."""

    a: Dict[str, str] = field(default_factory=dict)          # hostname -> ip
    srv: Dict[str, str] = field(default_factory=dict)        # instance -> target host
    txt: Dict[str, Dict[str, str]] = field(default_factory=dict)  # instance -> txt
    ptr: Set[str] = field(default_factory=set)               # instance names


def _parse_response(data: bytes, records: _Records) -> None:
    """Merge one response packet's answer records into ``records``."""
    if len(data) < 12:
        return

    try:
        _, _, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return

    offset = 12
    # Skip the question section; we only care about answers.
    for _ in range(qd_count):
        _, offset = _read_name(data, offset)
        offset += 4

    total_records = an_count + ns_count + ar_count
    for _ in range(total_records):
        if offset >= len(data):
            return
        name, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            return
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength

        if rtype == TYPE_A and rdlength == 4:
            records.a[name.lower()] = socket.inet_ntoa(rdata)
        elif rtype == TYPE_PTR:
            target, _ = _read_name(data, offset - rdlength)
            if target:
                records.ptr.add(target)
        elif rtype == TYPE_SRV and rdlength >= 6:
            # SRV rdata: priority(2) weight(2) port(2) target(name)
            target, _ = _read_name(data, offset - rdlength + 6)
            if target:
                records.srv[name] = target.lower()
        elif rtype == TYPE_TXT and rdlength:
            parsed = _parse_txt(rdata)
            if parsed:
                records.txt.setdefault(name, {}).update(parsed)


# --------------------------------------------------------------------------
# Socket handling
# --------------------------------------------------------------------------


def _make_listener() -> Optional[socket.socket]:
    """Try to bind 5353 and join the multicast group.

    Returns None when another responder (Bonjour, Avahi) owns the port and
    address reuse is unavailable -- a normal, non-fatal condition.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass  # Linux without SO_REUSEPORT support
        sock.bind(("", MDNS_PORT))
        membership = struct.pack("4sl", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.setblocking(False)
        return sock
    except OSError:
        sock.close()
        return None


def _make_querier() -> socket.socket:
    """Create the ephemeral-port socket used to send queries and get QU replies."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.bind(("", 0))
    sock.setblocking(False)
    return sock


def _collect(duration: float) -> Tuple[_Records, List[str]]:
    """Send queries and gather responses for ``duration`` seconds.

    Runs on a worker thread; uses ``select`` rather than asyncio datagram
    endpoints because those behave inconsistently with multicast on Windows.
    """
    import select

    warnings: List[str] = []
    records = _Records()

    try:
        querier = _make_querier()
    except OSError as exc:
        return records, [f"mDNS unavailable: could not open a UDP socket ({exc})."]

    listener = _make_listener()
    if listener is None:
        warnings.append(
            "mDNS multicast listener unavailable (port 5353 is in use by the system "
            "responder). Falling back to unicast replies only; some devices may be missed."
        )

    sockets = [s for s in (querier, listener) if s is not None]
    # Batch the query names: one packet per ~8 questions keeps us under the
    # typical 1500-byte MTU.
    batches = [SERVICE_QUERIES[i : i + 8] for i in range(0, len(SERVICE_QUERIES), 8)]

    deadline = time.monotonic() + duration
    next_send = 0.0
    sends_remaining = 2  # an initial burst plus one retry for lossy wifi

    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if sends_remaining > 0 and now >= next_send:
                for batch in batches:
                    packet = build_query(tuple(batch))
                    try:
                        querier.sendto(packet, (MDNS_ADDR, MDNS_PORT))
                    except OSError:
                        # No multicast route (e.g. VPN-only interface).
                        break
                sends_remaining -= 1
                next_send = now + max(1.0, duration / 3)

            timeout = min(0.3, max(0.0, deadline - time.monotonic()))
            readable, _, _ = select.select(sockets, [], [], timeout)
            for sock in readable:
                try:
                    data, _addr = sock.recvfrom(9000)
                except OSError:
                    continue
                _parse_response(data, records)
    finally:
        for sock in sockets:
            sock.close()

    return records, warnings


def _assemble(records: _Records) -> Dict[str, MdnsHost]:
    """Correlate A/SRV/PTR/TXT records into per-IP device facts."""
    hosts: Dict[str, MdnsHost] = {}

    def host_for(ip: str) -> MdnsHost:
        return hosts.setdefault(ip, MdnsHost(ip=ip))

    # A records give us hostname -> IP, the backbone of the mapping.
    for hostname, ip in records.a.items():
        entry = host_for(ip)
        pretty = hostname[: -len(".local")] if hostname.endswith(".local") else hostname
        entry.hostname = pretty or entry.hostname

    # SRV records attach a service instance to a hostname, and thus to an IP.
    for instance, target in records.srv.items():
        ip = records.a.get(target)
        if not ip:
            continue
        entry = host_for(ip)
        # "Living Room._airplay._tcp.local" -> "_airplay._tcp.local"
        match = _SERVICE_TYPE_RE.search(instance)
        if match:
            entry.services.add(match.group(1).lower())
        for key, value in records.txt.get(instance, {}).items():
            if key in INTERESTING_TXT_KEYS and value:
                entry.txt_hints.setdefault(key, value)

    return hosts


async def discover_via_mdns(duration: float = 2.5) -> Tuple[Dict[str, MdnsHost], List[str]]:
    """Run an mDNS sweep, returning per-IP results and any warnings."""
    return await asyncio.to_thread(lambda: _finish(_collect(duration)))


def _finish(collected: Tuple[_Records, List[str]]) -> Tuple[Dict[str, MdnsHost], List[str]]:
    records, warnings = collected
    return _assemble(records), warnings
