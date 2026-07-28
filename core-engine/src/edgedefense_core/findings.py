"""Turning raw scan observations into findings a human can act on.

Each finding carries four separate pieces of text:

``summary``      one line, shown in lists
``detail``       the plain-English "what this means and why it matters"
``what_to_do``   concrete next step
``limitations``  what this detection genuinely cannot know

The last field exists because the honest answer to "is this bad?" is often
"probably not, but here is how to check". Overstating findings to make the
output look impressive is the one failure mode this module is designed against.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .classify import friendly_type
from .discovery.ports import describe_port
from .models import Device, Finding

#: Ports that carry genuine, well-understood risk when reachable on a LAN.
#: Mapping: port -> (code, severity, short title).
_RISKY_PORTS: Dict[int, tuple[str, str, str]] = {
    23: ("telnet_exposed", "high", "Telnet is open"),
    2323: ("telnet_exposed", "high", "Telnet is open (alternate port)"),
    5555: ("adb_exposed", "high", "Android debug bridge is open"),
    21: ("ftp_exposed", "medium", "FTP is open"),
    5900: ("vnc_exposed", "medium", "VNC remote desktop is open"),
    7547: ("tr069_exposed", "medium", "ISP remote-management port is open"),
    3389: ("rdp_exposed", "medium", "Windows Remote Desktop is open"),
    445: ("smb_exposed", "low", "Windows file sharing is open"),
    139: ("smb_exposed", "low", "Windows file sharing is open"),
}

#: Databases that historically ship with no authentication at all.
_OPEN_DATABASE_PORTS = {
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    3306: "MySQL",
    5432: "PostgreSQL",
}

#: Above this many open ports, a home device is doing more than it should.
_PORT_COUNT_THRESHOLD = 8

#: Device types where an exposed legacy service strongly suggests the vendor
#: shipped default credentials -- the classic consumer-IoT failure mode.
_DEFAULT_CRED_TYPES = {"camera", "iot_generic", "smart_home", "router"}


def _make_id(code: str, device_id: Optional[str]) -> str:
    """Build a deterministic, readable finding id.

    Stability matters: the user may ask "explain that Telnet thing" several
    turns after the scan, and the id has to still resolve.
    """
    if device_id:
        return f"{code}:{device_id}"
    return code


def bare_name(device: Device) -> str:
    """A device name safe to place next to a separately-rendered IP address.

    The explanation templates read "{name} at {ip} is running...", so ``name``
    must not already contain the address -- ``Device.label()`` does include it
    for unidentified devices, which would render "the device at 1.2.3.4 at
    1.2.3.4". The forms here are lowercase and article-led so they also read
    correctly mid-sentence ("Check the Sonos device's settings page").
    """
    if device.user_label:
        return device.user_label
    if device.hostname:
        return device.hostname
    if device.vendor:
        return f"the {device.vendor} device"
    return "the unidentified device"


def sentence_name(device: Device) -> str:
    """:func:`bare_name` capitalised, for templates that open a sentence with it.

    A hostname is an identifier and is left exactly as the device reports it --
    "macm4 at 192.168.1.30 is..." is correct, "Macm4" is not. Only the generic
    article-led fallbacks are capitalised.
    """
    name = bare_name(device)
    if device.hostname or device.user_label:
        return name
    return name[0].upper() + name[1:]


def name_with_ip(device: Device) -> str:
    """Render "<name> (<ip>)" for summaries and titles, without repeating the IP."""
    label = device.label()
    return label if device.ip in label else f"{label} ({device.ip})"


def _device_findings(device: Device) -> List[Finding]:
    """Every finding derivable from a single device's Tier 0 data."""
    findings: List[Finding] = []
    # `name` goes into templates that also print {ip}; `where` is the
    # self-contained form used for titles and one-line summaries.
    name = bare_name(device)
    sentence = sentence_name(device)
    where = name_with_ip(device)
    seen_codes: set[str] = set()

    # --- Exposed services with known risk ------------------------------
    for port in device.open_ports:
        entry = _RISKY_PORTS.get(port)
        if not entry:
            continue
        code, severity, title = entry
        if code in seen_codes:
            continue  # e.g. 139 and 445 are the same underlying issue
        seen_codes.add(code)

        findings.append(
            Finding(
                finding_id=_make_id(code, device.device_id),
                code=code,
                severity=severity,
                title=f"{title} on {where}",
                summary=(
                    f"{where} is accepting connections on port {port} "
                    f"- {describe_port(port)}."
                ),
                detail=_EXPLANATIONS[code]["detail"].format(name=name, Name=sentence, ip=device.ip, port=port),
                what_to_do=_EXPLANATIONS[code]["what_to_do"].format(name=name, Name=sentence, ip=device.ip),
                limitations=_EXPLANATIONS[code]["limitations"],
                device_id=device.device_id,
                evidence={"port": port, "service": describe_port(port)},
            )
        )

    # --- Databases reachable from the LAN ------------------------------
    open_databases = [p for p in device.open_ports if p in _OPEN_DATABASE_PORTS]
    if open_databases:
        port = open_databases[0]
        engine = _OPEN_DATABASE_PORTS[port]
        findings.append(
            Finding(
                finding_id=_make_id("database_exposed", device.device_id),
                code="database_exposed",
                severity="medium",
                title=f"A {engine} database is reachable on {where}",
                summary=(
                    f"{where} is running {engine} on port {port}, "
                    "reachable from anywhere on this network."
                ),
                detail=_EXPLANATIONS["database_exposed"]["detail"].format(
                    name=name, Name=sentence, ip=device.ip, engine=engine, port=port
                ),
                what_to_do=_EXPLANATIONS["database_exposed"]["what_to_do"].format(
                    engine=engine, name=name, Name=sentence
                ),
                limitations=_EXPLANATIONS["database_exposed"]["limitations"],
                device_id=device.device_id,
                evidence={"port": port, "engine": engine},
            )
        )

    # --- Likely default credentials ------------------------------------
    legacy_open = [p for p in device.open_ports if p in (23, 2323, 21)]
    if legacy_open and device.device_type in _DEFAULT_CRED_TYPES:
        findings.append(
            Finding(
                finding_id=_make_id("default_credential_risk", device.device_id),
                code="default_credential_risk",
                severity="high",
                title=f"{where} matches the default-password risk pattern",
                summary=(
                    f"{where} looks like a {friendly_type(device.device_type).lower()} and "
                    f"exposes a legacy login service (port {legacy_open[0]}). Devices in this "
                    "category frequently ship with a factory password."
                ),
                detail=_EXPLANATIONS["default_credential_risk"]["detail"].format(
                    name=name, Name=sentence, ip=device.ip
                ),
                what_to_do=_EXPLANATIONS["default_credential_risk"]["what_to_do"].format(name=name, Name=sentence),
                limitations=_EXPLANATIONS["default_credential_risk"]["limitations"],
                device_id=device.device_id,
                evidence={"ports": legacy_open, "device_type": device.device_type},
            )
        )

    # --- Unusually broad attack surface ---------------------------------
    if len(device.open_ports) >= _PORT_COUNT_THRESHOLD:
        findings.append(
            Finding(
                finding_id=_make_id("many_open_ports", device.device_id),
                code="many_open_ports",
                severity="low",
                title=f"{where} has an unusually large number of open ports",
                summary=(
                    f"{where} is listening on {len(device.open_ports)} of the "
                    "ports checked, which is high for a home device."
                ),
                detail=_EXPLANATIONS["many_open_ports"]["detail"].format(
                    name=name, Name=sentence, count=len(device.open_ports)
                ),
                what_to_do=_EXPLANATIONS["many_open_ports"]["what_to_do"].format(name=name, Name=sentence),
                limitations=_EXPLANATIONS["many_open_ports"]["limitations"],
                device_id=device.device_id,
                evidence={"open_ports": list(device.open_ports)},
            )
        )

    # --- Devices we simply could not identify ---------------------------
    # A randomised MAC is expected modern behaviour, not a red flag, so those
    # get an informational note instead of a scored finding.
    unidentified = (
        device.device_type == "unknown"
        and not device.vendor
        and not device.hostname
        and not device.is_self
    )
    if unidentified and device.randomised_mac:
        findings.append(
            Finding(
                finding_id=_make_id("private_address_device", device.device_id),
                code="private_address_device",
                severity="info",
                title=f"A device at {device.ip} is using a private (randomised) address",
                summary=(
                    f"The device at {device.ip} rotates its hardware address for privacy, "
                    "so its manufacturer cannot be looked up. This is normal."
                ),
                detail=_EXPLANATIONS["private_address_device"]["detail"].format(ip=device.ip),
                what_to_do=_EXPLANATIONS["private_address_device"]["what_to_do"],
                limitations=_EXPLANATIONS["private_address_device"]["limitations"],
                device_id=device.device_id,
            )
        )
    elif unidentified:
        findings.append(
            Finding(
                finding_id=_make_id("unidentified_device", device.device_id),
                code="unidentified_device",
                severity="low",
                title=f"Unidentified device at {device.ip}",
                summary=(
                    f"The device at {device.ip} (hardware address {device.mac or 'unknown'}) "
                    "did not respond with a name and its manufacturer is not in the local "
                    "vendor database."
                ),
                detail=_EXPLANATIONS["unidentified_device"]["detail"].format(
                    ip=device.ip, mac=device.mac or "unknown"
                ),
                what_to_do=_EXPLANATIONS["unidentified_device"]["what_to_do"],
                limitations=_EXPLANATIONS["unidentified_device"]["limitations"],
                device_id=device.device_id,
                evidence={"mac": device.mac},
            )
        )

    return findings


def build_findings(devices: Iterable[Device]) -> List[Finding]:
    """Generate the full Tier 0 finding list, most severe first."""
    findings: List[Finding] = []
    for device in devices:
        findings.extend(_device_findings(device))
    return sort_findings(findings)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Order findings by severity (highest first), then by title for stability."""
    from .models import SEVERITY_ORDER

    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.title),
    )


def find_by_id(findings: Iterable[Finding], finding_id: str) -> Optional[Finding]:
    """Look up a finding, tolerating case differences in the id."""
    target = finding_id.strip().lower()
    for finding in findings:
        if finding.finding_id.lower() == target:
            return finding
    return None


# --------------------------------------------------------------------------
# Explanation copy
# --------------------------------------------------------------------------
# Kept as data rather than inline strings so the wording can be reviewed in one
# place. Tone: explain the mechanism, state the realistic risk, avoid alarm.

_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "telnet_exposed": {
        "detail": (
            "Telnet is a remote-login protocol from before encryption was standard. "
            "Everything it carries - including the password used to log in - travels "
            "across the network as readable text. {Name} at {ip} is accepting Telnet "
            "connections on port {port}.\n\n"
            "This matters for two reasons. Anyone already on this network can read those "
            "credentials off the wire. And Telnet is the single most common way that "
            "internet-scanning malware takes over home devices, because so many shipped "
            "with a factory username and password that was never changed."
        ),
        "what_to_do": (
            "Check {name}'s settings page for an option to disable Telnet - most devices "
            "have one, and most do not need it enabled. If the device offers SSH instead, "
            "use that. If Telnet cannot be turned off and the device is not essential, "
            "consider replacing it or moving it to a guest network."
        ),
        "limitations": (
            "This check confirms the port accepts connections. It does not attempt to log "
            "in, so it cannot tell you whether the password is still the factory default."
        ),
    },
    "adb_exposed": {
        "detail": (
            "Port {port} on {name} ({ip}) is running the Android Debug Bridge. ADB is a "
            "development tool that grants near-complete control of the device - installing "
            "software, reading files, running commands - and over the network it typically "
            "does so without asking for any password.\n\n"
            "This is most often found on Android TV boxes and streaming sticks where "
            "developer mode was switched on and never switched back off."
        ),
        "what_to_do": (
            "On {name}, open Settings, find Developer Options, and turn off 'USB debugging' "
            "or 'Network debugging' / 'ADB over network'. If you do not recognise this "
            "device at all, that is worth investigating before anything else."
        ),
        "limitations": (
            "Some devices require an on-screen authorisation prompt before an ADB client "
            "can connect. This check cannot tell whether that protection is in place."
        ),
    },
    "ftp_exposed": {
        "detail": (
            "{Name} at {ip} is running an FTP server on port {port}. Like Telnet, classic "
            "FTP sends usernames and passwords without encryption, and many devices that "
            "enable it also allow anonymous access to whatever files are being shared.\n\n"
            "On a home network the realistic risk is moderate: someone would need to already "
            "be connected to your wifi. It becomes serious if the router also forwards this "
            "port to the internet."
        ),
        "what_to_do": (
            "Check whether you actually use FTP on {name}. If not, disable it. If you do "
            "need file access, SFTP or SMB with a password are both better options. Also "
            "confirm your router is not forwarding port 21 to the internet."
        ),
        "limitations": (
            "This does not test whether anonymous login is permitted or what files are "
            "shared - only that an FTP service answered."
        ),
    },
    "vnc_exposed": {
        "detail": (
            "Port {port} on {name} ({ip}) is a VNC server, which shares the device's screen "
            "and accepts mouse and keyboard input from across the network.\n\n"
            "VNC's built-in password scheme is weak by modern standards, and some VNC "
            "servers can be configured with no password at all. Anyone who can reach this "
            "port and get past authentication is effectively sitting at the machine."
        ),
        "what_to_do": (
            "If you did not deliberately set up remote desktop access on {name}, turn it "
            "off. If you did, make sure it requires a strong password, and prefer tunnelling "
            "it over SSH or a VPN rather than exposing it directly."
        ),
        "limitations": (
            "This check does not attempt authentication, so it cannot report whether the "
            "server is password-protected."
        ),
    },
    "rdp_exposed": {
        "detail": (
            "{Name} at {ip} has Windows Remote Desktop listening on port {port}. This is a "
            "legitimate and commonly used feature, so on its own it is not a problem.\n\n"
            "It is flagged because RDP is a high-value target: it grants full interactive "
            "access to the machine, and automated password-guessing against it is constant "
            "and relentless wherever it is reachable from the internet."
        ),
        "what_to_do": (
            "If you use Remote Desktop on {name}, keep it - but ensure the account it uses "
            "has a strong password and that your router is not forwarding port 3389 to the "
            "internet. If you do not use it, disable it under System > Remote Desktop."
        ),
        "limitations": (
            "This is a surface observation. It says nothing about password strength, "
            "account lockout policy, or whether Network Level Authentication is required."
        ),
    },
    "tr069_exposed": {
        "detail": (
            "Port {port} on {name} ({ip}) is the TR-069 management interface. Internet "
            "providers use it to configure and update routers remotely.\n\n"
            "Seeing it on your own network is usually expected on an ISP-supplied router. "
            "It is worth knowing about because it is a powerful interface that you do not "
            "control, and because flaws in TR-069 implementations have been used to "
            "compromise large numbers of home routers at once."
        ),
        "what_to_do": (
            "If {name} is a router your internet provider supplied, this is normal and you "
            "generally cannot disable it. Keep the router's firmware current. If you own "
            "the router outright, check whether remote management can be switched off."
        ),
        "limitations": (
            "Presence of this port is not evidence of a problem. It is reported for "
            "awareness, and is weighted lightly in the trust score for that reason."
        ),
    },
    "smb_exposed": {
        "detail": (
            "{Name} at {ip} is sharing files over SMB, the Windows file-sharing protocol, "
            "on port {port}. On a home network this is completely normal - it is how shared "
            "folders, network drives, and most NAS boxes work.\n\n"
            "It is listed so you know what is reachable. The thing worth checking is whether "
            "the shares require a password, and whether the device still speaks the obsolete "
            "SMBv1 protocol."
        ),
        "what_to_do": (
            "Confirm the shares on {name} need a password rather than allowing guest access, "
            "and that SMBv1 is disabled. On a NAS this is usually under a 'File Services' "
            "settings page."
        ),
        "limitations": (
            "This check cannot see which shares exist, whether they are password-protected, "
            "or which SMB version is in use."
        ),
    },
    "database_exposed": {
        "detail": (
            "{Name} at {ip} is running {engine} on port {port}, and it is answering "
            "connections from the network rather than only from the machine itself.\n\n"
            "Redis, MongoDB and Elasticsearch in particular have historically shipped with "
            "no authentication enabled by default, which is why they are worth flagging. If "
            "this is a database you set up, the question to answer is simply whether it "
            "requires a password."
        ),
        "what_to_do": (
            "If you run {engine} intentionally on {name}, bind it to 127.0.0.1 unless other "
            "machines genuinely need it, and enable authentication. If you did not set this "
            "up, find out what installed it."
        ),
        "limitations": (
            "This check does not attempt to authenticate or read any data, so it cannot "
            "confirm whether the database is actually unprotected."
        ),
    },
    "default_credential_risk": {
        "detail": (
            "{Name} at {ip} combines two things that are risky together: it looks like an "
            "appliance-style device (camera, smart-home gadget, or router), and it exposes "
            "a legacy login service.\n\n"
            "This is the exact pattern that large IoT botnets are built from. The devices "
            "involved are rarely compromised through anything sophisticated - they are "
            "found by automated scanning and entered with the manufacturer's default "
            "username and password, which was never changed because most people never knew "
            "there was one."
        ),
        "what_to_do": (
            "Log into {name}'s admin interface and change the password if it is still the "
            "default. Disable Telnet and FTP if the device allows it. Then check for a "
            "firmware update - devices in this category often ship with known, already-patched "
            "vulnerabilities."
        ),
        "limitations": (
            "This is a pattern match on device type and open ports. It is not proof that "
            "default credentials are in use - only that this device fits the profile where "
            "they usually are. Verifying requires trying to log in, which this tool does "
            "not do."
        ),
    },
    "many_open_ports": {
        "detail": (
            "{Name} is listening on {count} of the ports checked. Most home devices listen "
            "on one or two.\n\n"
            "A high count is not automatically bad - a home server, NAS, or development "
            "machine legitimately runs many services. It is flagged because a device "
            "offering more services than it needs has more ways to be attacked, and because "
            "an unexpected jump here is a useful signal that something was installed that "
            "you did not intend."
        ),
        "what_to_do": (
            "If {name} is a server you administer, this is probably expected - review the "
            "list and turn off anything unused. If it is an appliance that should be doing "
            "one job, the extra services are worth investigating."
        ),
        "limitations": (
            "Only a fixed list of common ports is checked, so this count is a sample rather "
            "than a complete inventory of what the device is running."
        ),
    },
    "unidentified_device": {
        "detail": (
            "A device at {ip} with hardware address {mac} responded to network traffic, but "
            "gave no name, advertised no services, and its manufacturer prefix is not in the "
            "bundled vendor database.\n\n"
            "The most common explanation is mundane: an older or obscure device, or one "
            "configured to stay quiet. It is listed because 'what is that?' is a question "
            "worth being able to answer about your own network, and because an unrecognised "
            "device is the starting point for noticing an unwanted one."
        ),
        "what_to_do": (
            "Try to account for it. Switching a suspected device off and re-scanning is the "
            "quickest way to confirm which one it is. If it turns out to be nothing you own, "
            "change your wifi password."
        ),
        "limitations": (
            "The bundled vendor database is a curated subset of the full IEEE registry, so "
            "'unknown manufacturer' sometimes just means the prefix is not in the local copy. "
            "Devices using a randomised address are reported separately and are not counted "
            "against the score."
        ),
    },
    "private_address_device": {
        "detail": (
            "The device at {ip} is using a randomised hardware address. Phones, tablets and "
            "laptops from roughly 2020 onward do this by default - they present a different "
            "address to each network so that they cannot be tracked between locations.\n\n"
            "The practical effect is that the manufacturer cannot be identified. This is a "
            "privacy feature working as designed, and is reported for completeness rather "
            "than as a concern."
        ),
        "what_to_do": (
            "Nothing. If you want the device to be identifiable on your own network, most "
            "phones offer a per-network 'use private address' toggle that can be turned off."
        ),
        "limitations": (
            "A randomised address is indistinguishable from a deliberately spoofed one. This "
            "is not counted against the trust score in either case, because doing so would "
            "penalise every modern phone."
        ),
    },
}


def explanation_for_code(code: str) -> Optional[Dict[str, str]]:
    """Expose the explanation copy for a finding code, for tests and reuse."""
    return _EXPLANATIONS.get(code)


#: Public aliases so other modules can build
#: findings with identical ids and wording without reaching into privates.
EXPLANATIONS = _EXPLANATIONS
make_finding_id = _make_id
