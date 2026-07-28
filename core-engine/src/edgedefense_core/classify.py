"""Best-guess device type identification.

This is explicitly a *guess*. Every result carries a confidence level, and the
formatting layer is expected to surface uncertainty rather than hide it -- an
overconfident wrong label is worse than an honest "unknown".

Evidence is weighted roughly in order of reliability:
    mDNS service types  >  hostname keywords  >  open ports  >  vendor name
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

#: mDNS service type -> (device_type, confidence). These are the strongest
#: signal available because the device is stating what it is.
_MDNS_SIGNALS: Dict[str, Tuple[str, str]] = {
    "_googlecast._tcp.local": ("tv_or_streaming", "high"),
    "_androidtvremote2._tcp.local": ("tv_or_streaming", "high"),
    "_roku-rcp._tcp.local": ("tv_or_streaming", "high"),
    "_amzn-wplay._tcp.local": ("tv_or_streaming", "high"),
    # AirPlay is advertised by TVs, speakers and Macs alike, so on its own it
    # is genuinely ambiguous and must not outrank a specific signal.
    "_airplay._tcp.local": ("tv_or_streaming", "low"),
    # AirPlay *audio*, by contrast, means a speaker.
    "_raop._tcp.local": ("smart_speaker", "medium"),
    "_spotify-connect._tcp.local": ("smart_speaker", "medium"),
    "_sonos._tcp.local": ("smart_speaker", "high"),
    "_ipp._tcp.local": ("printer", "high"),
    "_ipps._tcp.local": ("printer", "high"),
    "_printer._tcp.local": ("printer", "high"),
    "_pdl-datastream._tcp.local": ("printer", "high"),
    "_scanner._tcp.local": ("printer", "high"),
    "_smb._tcp.local": ("nas_or_server", "low"),
    "_afpovertcp._tcp.local": ("nas_or_server", "medium"),
    "_nfs._tcp.local": ("nas_or_server", "medium"),
    "_plexmediasvr._tcp.local": ("nas_or_server", "high"),
    "_workstation._tcp.local": ("computer", "medium"),
    "_companion-link._tcp.local": ("computer", "low"),
    "_sftp-ssh._tcp.local": ("computer", "medium"),
    "_ssh._tcp.local": ("computer", "medium"),
    # Screen sharing / VNC. Appliances do not offer a desktop; computers do.
    "_rfb._tcp.local": ("computer", "high"),
    "_hap._tcp.local": ("smart_home", "high"),
    "_homekit._tcp.local": ("smart_home", "high"),
    "_matter._tcp.local": ("smart_home", "high"),
    "_matterc._udp.local": ("smart_home", "high"),
    "_hue._tcp.local": ("smart_home", "high"),
    "_nanoleafapi._tcp.local": ("smart_home", "high"),
    "_esphomelib._tcp.local": ("smart_home", "high"),
    "_home-assistant._tcp.local": ("nas_or_server", "high"),
}

#: Substrings that commonly appear in hostnames, mapped to a device type.
_HOSTNAME_SIGNALS: Tuple[Tuple[str, str, str], ...] = (
    ("iphone", "phone_or_tablet", "high"),
    ("ipad", "phone_or_tablet", "high"),
    ("android", "phone_or_tablet", "high"),
    ("pixel", "phone_or_tablet", "high"),
    ("galaxy", "phone_or_tablet", "high"),
    ("macbook", "computer", "high"),
    ("imac", "computer", "high"),
    ("desktop-", "computer", "high"),
    ("laptop", "computer", "high"),
    ("-pc", "computer", "medium"),
    ("raspberrypi", "nas_or_server", "high"),
    ("synology", "nas_or_server", "high"),
    ("diskstation", "nas_or_server", "high"),
    ("truenas", "nas_or_server", "high"),
    ("freenas", "nas_or_server", "high"),
    ("unraid", "nas_or_server", "high"),
    ("nas", "nas_or_server", "medium"),
    ("printer", "printer", "high"),
    ("officejet", "printer", "high"),
    ("deskjet", "printer", "high"),
    ("laserjet", "printer", "high"),
    ("envy", "printer", "medium"),
    ("brother", "printer", "medium"),
    ("chromecast", "tv_or_streaming", "high"),
    ("firetv", "tv_or_streaming", "high"),
    ("shield", "tv_or_streaming", "medium"),
    ("roku", "tv_or_streaming", "high"),
    ("appletv", "tv_or_streaming", "high"),
    ("apple-tv", "tv_or_streaming", "high"),
    ("bravia", "tv_or_streaming", "high"),
    ("samsungtv", "tv_or_streaming", "high"),
    ("echo", "smart_speaker", "medium"),
    ("alexa", "smart_speaker", "high"),
    ("homepod", "smart_speaker", "high"),
    ("sonos", "smart_speaker", "high"),
    ("nest", "smart_home", "medium"),
    ("hue", "smart_home", "high"),
    ("wemo", "smart_home", "high"),
    ("shelly", "smart_home", "high"),
    ("tasmota", "smart_home", "high"),
    ("esp-", "iot_generic", "medium"),
    ("esp32", "iot_generic", "high"),
    ("esp8266", "iot_generic", "high"),
    ("camera", "camera", "high"),
    ("cam-", "camera", "medium"),
    ("ipcam", "camera", "high"),
    ("doorbell", "camera", "high"),
    ("ring-", "camera", "high"),
    ("wyze", "camera", "high"),
    ("router", "router", "high"),
    ("gateway", "router", "medium"),
    ("openwrt", "router", "high"),
    ("unifi", "router", "medium"),
    ("eero", "router", "high"),
    ("playstation", "game_console", "high"),
    ("ps5", "game_console", "high"),
    ("xbox", "game_console", "high"),
    ("nintendo", "game_console", "high"),
    ("switch", "game_console", "medium"),
)

#: Vendor name substring -> (device_type, confidence). Weakest signal: a vendor
#: like Apple or Samsung makes many different kinds of device.
_VENDOR_SIGNALS: Tuple[Tuple[str, str, str], ...] = (
    ("sonos", "smart_speaker", "high"),
    ("roku", "tv_or_streaming", "high"),
    ("philips hue", "smart_home", "high"),
    ("lifx", "smart_home", "high"),
    ("ecobee", "smart_home", "high"),
    ("chamberlain", "smart_home", "high"),
    ("tuya", "smart_home", "high"),
    ("irobot", "smart_home", "high"),
    ("ring", "camera", "high"),
    ("wyze", "camera", "high"),
    ("hikvision", "camera", "high"),
    ("axis communications", "camera", "high"),
    ("espressif", "iot_generic", "medium"),
    ("raspberry pi", "nas_or_server", "medium"),
    ("qnap", "nas_or_server", "high"),
    ("synology", "nas_or_server", "high"),
    ("hewlett packard", "printer", "low"),
    ("brother", "printer", "medium"),
    ("epson", "printer", "medium"),
    ("canon", "printer", "medium"),
    ("xerox", "printer", "medium"),
    ("netgear", "router", "medium"),
    ("ubiquiti", "router", "medium"),
    ("tp-link", "router", "low"),
    ("d-link", "router", "low"),
    ("arris", "router", "high"),
    ("technicolor", "router", "high"),
    ("zyxel", "router", "medium"),
    ("cisco-linksys", "router", "medium"),
    ("asustek", "router", "low"),
    ("playstation", "game_console", "high"),
    ("nintendo", "game_console", "high"),
    ("intel", "computer", "medium"),
    ("dell", "computer", "medium"),
    ("vmware", "nas_or_server", "high"),
    ("virtualbox", "nas_or_server", "high"),
    ("qemu", "nas_or_server", "high"),
    ("hon hai", "computer", "low"),
    ("foxconn", "computer", "low"),
)

#: Port fingerprints, checked as a set-membership test.
_PORT_SIGNALS: Tuple[Tuple[Tuple[int, ...], str, str], ...] = (
    ((9100, 515, 631), "printer", "high"),
    ((554,), "camera", "medium"),
    ((32400,), "nas_or_server", "high"),
    ((8123,), "nas_or_server", "high"),
    ((2049, 445, 873), "nas_or_server", "low"),
    ((3389,), "computer", "medium"),
    ((1400,), "smart_speaker", "high"),
    ((7547,), "router", "high"),
    ((5555,), "tv_or_streaming", "low"),
)

_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _better(current: Tuple[str, str], candidate: Tuple[str, str]) -> Tuple[str, str]:
    """Keep whichever guess carries the higher confidence."""
    if _CONFIDENCE_RANK[candidate[1]] > _CONFIDENCE_RANK[current[1]]:
        return candidate
    return current


def classify_device(
    *,
    hostname: Optional[str] = None,
    user_label: Optional[str] = None,
    vendor: Optional[str] = None,
    open_ports: Optional[Iterable[int]] = None,
    mdns_services: Optional[Iterable[str]] = None,
    txt_hints: Optional[Dict[str, str]] = None,
    is_gateway: bool = False,
    is_self: bool = False,
) -> Tuple[str, str]:
    """Guess a device type from all available evidence.

    Returns:
        A ``(device_type, confidence)`` pair. ``device_type`` is one of the
        slugs in ``models.DEVICE_TYPES``; ``confidence`` is
        "high" | "medium" | "low" | "none".
    """
    # Two cases are known rather than inferred, so they short-circuit: the
    # default gateway is the router, and the host running the scan is a
    # computer. Letting weaker evidence override either would be a regression.
    if is_gateway:
        return ("router", "high")
    if is_self:
        return ("computer", "high")

    guess: Tuple[str, str] = ("unknown", "none")

    # 1. mDNS service advertisements -- the device telling us what it is.
    for service in mdns_services or ():
        signal = _MDNS_SIGNALS.get(service.lower())
        if signal:
            guess = _better(guess, signal)

    # 2. Hostname keywords, user-assigned names, plus model strings from mDNS TXT.
    searchable = (hostname or "").lower()
    if user_label:
        searchable += " " + user_label.lower()
    for value in (txt_hints or {}).values():
        searchable += " " + value.lower()

    if searchable.strip():
        for needle, device_type, confidence in _HOSTNAME_SIGNALS:
            if needle in searchable:
                guess = _better(guess, (device_type, confidence))

    # 3. Open ports.
    ports = set(open_ports or ())
    if ports:
        for signature, device_type, confidence in _PORT_SIGNALS:
            if ports & set(signature):
                guess = _better(guess, (device_type, confidence))

    # 4. Vendor -- weakest, so it only fills gaps left by everything above.
    if vendor:
        vendor_lower = vendor.lower()
        for needle, device_type, confidence in _VENDOR_SIGNALS:
            if needle in vendor_lower:
                guess = _better(guess, (device_type, confidence))

    return guess


#: Display labels per device type: (title-case singular, lowercase singular,
#: lowercase plural). English plurals here are irregular enough ("TVs or
#: streaming devices", "servers or NAS devices") that appending "s" produces
#: visible nonsense, so all three forms are written out.
_TYPE_LABELS: Dict[str, Tuple[str, str, str]] = {
    "router": ("Router / gateway", "router", "routers"),
    "computer": ("Computer", "computer", "computers"),
    "phone_or_tablet": ("Phone or tablet", "phone or tablet", "phones and tablets"),
    "tv_or_streaming": (
        "TV or streaming device",
        "TV or streaming device",
        "TVs and streaming devices",
    ),
    "smart_speaker": ("Smart speaker", "smart speaker", "smart speakers"),
    "camera": ("Camera", "camera", "cameras"),
    "printer": ("Printer", "printer", "printers"),
    "smart_home": ("Smart home device", "smart home device", "smart home devices"),
    "nas_or_server": ("Server or NAS", "server or NAS", "servers and NAS devices"),
    "game_console": ("Game console", "game console", "game consoles"),
    "iot_generic": ("Generic IoT device", "generic IoT device", "generic IoT devices"),
    "unknown": ("Unidentified", "unidentified device", "unidentified devices"),
}

_UNKNOWN_LABELS = _TYPE_LABELS["unknown"]


def friendly_type(device_type: str) -> str:
    """Human-readable label for a device type slug."""
    return _TYPE_LABELS.get(device_type, _UNKNOWN_LABELS)[0]


def type_count_label(device_type: str, count: int) -> str:
    """Render "3 smart speakers" / "1 phone or tablet" with a correct plural."""
    _, singular, plural_form = _TYPE_LABELS.get(device_type, _UNKNOWN_LABELS)
    return f"{count} {singular if count == 1 else plural_form}"


def summarise_types(device_types: List[str]) -> List[Tuple[str, int]]:
    """Count devices per type, most common first. Used by the scan summary."""
    counts: Dict[str, int] = {}
    for device_type in device_types:
        counts[device_type] = counts.get(device_type, 0) + 1
    return sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
