"""Wi-Fi link quality: signal, band, channel, and how crowded that channel is.

Most "my internet is slow" complaints on a home network are a Wi-Fi problem
rather than an internet problem, and the two have completely different fixes.
This module produces the evidence needed to tell them apart: how strong the
link actually is, what rate it negotiated, and how many neighbouring networks
are sitting on the same channel.

Nothing here transmits. Scanning for nearby networks is a passive read of
beacon frames the radio already receives.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ._proc import parse_float, parse_int, run, split_key_value

#: The airport binary Apple removed in later macOS releases. Tried first
#: because when it exists it is by far the cleanest source.
_AIRPORT = (
    "/System/Library/PrivateFrameworks/Apple80211.framework/"
    "Versions/Current/Resources/airport"
)

#: On 2.4 GHz only these three channels do not overlap each other. Anything
#: else guarantees interference with at least one neighbour.
_CLEAN_24_CHANNELS = (1, 6, 11)


@dataclass
class WifiLink:
    """The connection this machine currently holds."""

    ssid: Optional[str] = None
    bssid: Optional[str] = None
    band: Optional[str] = None
    channel: Optional[int] = None
    signal_percent: Optional[int] = None
    signal_dbm: Optional[float] = None
    rx_rate_mbps: Optional[float] = None
    tx_rate_mbps: Optional[float] = None
    radio_type: Optional[str] = None
    authentication: Optional[str] = None

    def quality(self) -> Optional[str]:
        """Signal strength as a word, using the usual dBm thresholds."""
        dbm = self.signal_dbm
        if dbm is None:
            return None
        if dbm >= -50:
            return "excellent"
        if dbm >= -60:
            return "good"
        if dbm >= -70:
            return "usable"
        if dbm >= -80:
            return "weak"
        return "very weak"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "band": self.band,
            "channel": self.channel,
            "signal_percent": self.signal_percent,
            "signal_dbm": self.signal_dbm,
            "signal_quality": self.quality(),
            "rx_rate_mbps": self.rx_rate_mbps,
            "tx_rate_mbps": self.tx_rate_mbps,
            "radio_type": self.radio_type,
            "authentication": self.authentication,
        }


@dataclass
class NearbyNetwork:
    """A network the radio can hear but is not joined to."""

    ssid: Optional[str] = None
    bssid: Optional[str] = None
    channel: Optional[int] = None
    band: Optional[str] = None
    signal_percent: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "band": self.band,
            "signal_percent": self.signal_percent,
        }


@dataclass
class WifiReport:
    """Link quality plus the radio environment around it."""

    link: Optional[WifiLink] = None
    nearby: List[NearbyNetwork] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def channel_usage(self) -> List[Tuple[int, int]]:
        """How many networks sit on each channel, busiest first."""
        counts: Dict[int, int] = {}
        for network in self.nearby:
            if network.channel:
                counts[network.channel] = counts.get(network.channel, 0) + 1
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))

    def congestion(self) -> Optional[int]:
        """Other networks sharing our exact channel, or None if unknown.

        The scan includes the access point we are joined to, so it has to be
        excluded or every reading is one too high. Matching on BSSID rather
        than SSID matters for mesh networks, where several genuinely separate
        radios share one name and each does contend for airtime.
        """
        if not self.link or not self.link.channel or not self.nearby:
            return None

        own_bssid = (self.link.bssid or "").lower()
        own_ssid = (self.link.ssid or "").lower()

        count = 0
        for network in self.nearby:
            if network.channel != self.link.channel:
                continue
            if own_bssid and (network.bssid or "").lower() == own_bssid:
                continue
            # Without a BSSID to compare, fall back to the name. Less precise,
            # but better than counting ourselves as our own interference.
            if not own_bssid and own_ssid and (network.ssid or "").lower() == own_ssid:
                continue
            count += 1
        return count

    def advice(self) -> List[str]:
        """Concrete, non-obvious things worth doing about what was measured.

        Deliberately conservative: only says something when a specific measured
        value justifies it. Generic Wi-Fi tips are not worth the user's time.
        """
        tips: List[str] = []
        link = self.link
        if link is None:
            return tips

        quality = link.quality()
        if quality in ("weak", "very weak"):
            tips.append(
                f"Signal is {quality} ({link.signal_dbm:.0f} dBm). At this strength the "
                "radio drops to a slower, more robust encoding, so throughput falls "
                "well below what the connection is capable of. Moving closer to the "
                "router, or adding an access point, will do more than any speed-test "
                "tuning."
            )

        crowded = self.congestion()
        if crowded is not None and crowded >= 3:
            tips.append(
                f"{crowded} other networks share channel {link.channel}. Devices on a "
                "shared channel take turns transmitting, so a crowded channel costs "
                "real throughput even when the signal is strong. Changing the router's "
                "channel is usually a one-setting fix."
            )

        if link.band and link.band.startswith("2.4") and link.channel:
            if link.channel not in _CLEAN_24_CHANNELS:
                tips.append(
                    f"On 2.4 GHz, channel {link.channel} partially overlaps its "
                    "neighbours. Only channels 1, 6 and 11 avoid that entirely."
                )
            if quality in ("excellent", "good"):
                tips.append(
                    "The signal is strong enough for 5 GHz, which is far less crowded "
                    "and much faster. If the router advertises both bands under one "
                    "name, this device chose 2.4 GHz anyway - worth checking."
                )

        return tips

    def to_dict(self) -> Dict[str, Any]:
        return {
            "link": self.link.to_dict() if self.link else None,
            "nearby_count": len(self.nearby),
            "nearby": [network.to_dict() for network in self.nearby],
            "channel_usage": [
                {"channel": channel, "networks": count}
                for channel, count in self.channel_usage()
            ],
            "same_channel_networks": self.congestion(),
            "advice": self.advice(),
            "warnings": self.warnings,
        }


def band_for_channel(channel: Optional[int]) -> Optional[str]:
    """Map a channel number to its frequency band."""
    if not channel:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 196:
        return "5 GHz"
    if 197 <= channel <= 233:
        return "6 GHz"
    return None


def percent_to_dbm(percent: Optional[int]) -> Optional[float]:
    """Convert Windows' signal percentage to dBm.

    Windows reports quality as a percentage derived from dBm by the inverse of
    this formula, so the conversion is exact rather than an approximation --
    but it is also lossy at the extremes, where the underlying scale is clamped.
    """
    if percent is None:
        return None
    return (percent / 2.0) - 100.0


# --------------------------------------------------------------------------
# Windows
# --------------------------------------------------------------------------


def parse_netsh_interfaces(text: str) -> Optional[WifiLink]:
    """Parse ``netsh wlan show interfaces`` output."""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        pair = split_key_value(line)
        if pair:
            values[pair[0].lower()] = pair[1]

    if not values.get("ssid") or values.get("state", "connected").lower() == "disconnected":
        return None

    channel = parse_int(values.get("channel"))
    percent = parse_int(values.get("signal"))
    band = values.get("band") or band_for_channel(channel)

    return WifiLink(
        ssid=values.get("ssid"),
        bssid=values.get("bssid"),
        band=band,
        channel=channel,
        signal_percent=percent,
        signal_dbm=percent_to_dbm(percent),
        rx_rate_mbps=parse_float(values.get("receive rate (mbps)")),
        tx_rate_mbps=parse_float(values.get("transmit rate (mbps)")),
        radio_type=values.get("radio type"),
        authentication=values.get("authentication"),
    )


def parse_netsh_networks(text: str) -> List[NearbyNetwork]:
    """Parse ``netsh wlan show networks mode=bssid``.

    One SSID block can list several BSSIDs (a mesh, or one router per band).
    Each is counted separately because each occupies its own channel.
    """
    networks: List[NearbyNetwork] = []
    current_ssid: Optional[str] = None
    pending: Optional[NearbyNetwork] = None

    for line in text.splitlines():
        pair = split_key_value(line)
        if not pair:
            continue
        key, value = pair[0].lower(), pair[1]

        if key.startswith("ssid") and not key.startswith("bssid"):
            current_ssid = value or "(hidden)"
        elif key.startswith("bssid"):
            if pending is not None:
                networks.append(pending)
            pending = NearbyNetwork(ssid=current_ssid, bssid=value or None)
        elif pending is not None:
            if key == "signal":
                pending.signal_percent = parse_int(value)
            elif key == "channel":
                pending.channel = parse_int(value)
                pending.band = band_for_channel(pending.channel)

    if pending is not None:
        networks.append(pending)
    return networks


async def _collect_windows(include_nearby: bool) -> WifiReport:
    report = WifiReport()
    report.link = parse_netsh_interfaces(
        await run(["netsh", "wlan", "show", "interfaces"])
    )
    if include_nearby:
        report.nearby = parse_netsh_networks(
            await run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=15.0)
        )
    return report


# --------------------------------------------------------------------------
# macOS
# --------------------------------------------------------------------------


def parse_airport_info(text: str) -> Optional[WifiLink]:
    """Parse ``airport -I`` output."""
    values: Dict[str, str] = {}
    for line in text.splitlines():
        pair = split_key_value(line)
        if pair:
            values[pair[0].lower()] = pair[1]

    if not values.get("ssid"):
        return None

    # airport reports "44,80": the primary channel and the width.
    channel = parse_int((values.get("channel") or "").split(",")[0])
    rssi = parse_float(values.get("agrctlrssi"))

    return WifiLink(
        ssid=values.get("ssid"),
        bssid=values.get("bssid"),
        band=band_for_channel(channel),
        channel=channel,
        signal_dbm=rssi,
        rx_rate_mbps=parse_float(values.get("maxrate")),
        tx_rate_mbps=parse_float(values.get("lasttxrate")),
        radio_type=values.get("link auth"),
        authentication=values.get("link auth"),
    )


def parse_airport_scan(text: str) -> List[NearbyNetwork]:
    """Parse the fixed-width table from ``airport -s``."""
    networks: List[NearbyNetwork] = []
    lines = text.splitlines()
    for line in lines[1:]:  # Skip the header row.
        # SSID may contain spaces, so anchor on the BSSID that follows it.
        match = re.search(
            r"((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})\s+(-?\d+)\s+(\d+)", line
        )
        if not match:
            continue
        ssid = line[: match.start()].strip() or "(hidden)"
        channel = int(match.group(3))
        networks.append(
            NearbyNetwork(
                ssid=ssid,
                bssid=match.group(1),
                channel=channel,
                band=band_for_channel(channel),
                signal_percent=None,
            )
        )
    return networks


async def _collect_macos(include_nearby: bool) -> WifiReport:
    report = WifiReport()
    report.link = parse_airport_info(await run([_AIRPORT, "-I"]))

    if report.link is None:
        # airport was removed in recent macOS; system_profiler still reports
        # the same facts, just more slowly and in a different shape.
        report.link = _parse_system_profiler(
            await run(["system_profiler", "SPAirPortDataType"], timeout=20.0)
        )
        if report.link is None:
            report.warnings.append(
                "Wi-Fi details were not available. Recent macOS releases removed the "
                "airport tool, and the fallback reported nothing usable."
            )

    if include_nearby:
        report.nearby = parse_airport_scan(await run([_AIRPORT, "-s"], timeout=20.0))
        if not report.nearby:
            report.warnings.append(
                "Could not scan for nearby networks, so channel congestion is unknown."
            )
    return report


def _parse_system_profiler(text: str) -> Optional[WifiLink]:
    """Pull the current link out of system_profiler's indented report."""
    if "Current Network Information" not in text:
        return None
    section = text.split("Current Network Information", 1)[1]

    def field_value(label: str) -> Optional[str]:
        match = re.search(rf"^\s*{re.escape(label)}:\s*(.+)$", section, re.MULTILINE)
        return match.group(1).strip() if match else None

    # The network name is the sole bare "Name:"-less heading under the section.
    name_match = re.search(r"^\s+([^\s:][^:]*):\s*$", section, re.MULTILINE)
    channel_raw = field_value("Channel")
    channel = parse_int(channel_raw)

    return WifiLink(
        ssid=name_match.group(1).strip() if name_match else None,
        bssid=None,
        band=("6 GHz" if "6GHz" in (channel_raw or "") else band_for_channel(channel)),
        channel=channel,
        signal_dbm=parse_float(field_value("Signal / Noise")),
        tx_rate_mbps=parse_float(field_value("Transmit Rate")),
        radio_type=field_value("PHY Mode"),
        authentication=field_value("Security"),
    )


# --------------------------------------------------------------------------
# Linux
# --------------------------------------------------------------------------


def parse_nmcli(text: str) -> Tuple[Optional[WifiLink], List[NearbyNetwork]]:
    """Parse terse ``nmcli -t -f ...`` output into the link and its neighbours.

    nmcli escapes colons inside BSSIDs as ``\\:``, which would otherwise make
    the field separator ambiguous.
    """
    link: Optional[WifiLink] = None
    nearby: List[NearbyNetwork] = []

    for line in text.splitlines():
        if not line.strip():
            continue
        fields = re.split(r"(?<!\\):", line)
        fields = [field.replace("\\:", ":") for field in fields]
        if len(fields) < 6:
            continue
        active, ssid, bssid, channel_raw, signal_raw, rate_raw = fields[:6]

        channel = parse_int(channel_raw)
        entry = NearbyNetwork(
            ssid=ssid or "(hidden)",
            bssid=bssid or None,
            channel=channel,
            band=band_for_channel(channel),
            signal_percent=parse_int(signal_raw),
        )
        nearby.append(entry)

        if active.lower() == "yes" and link is None:
            percent = parse_int(signal_raw)
            rate = parse_float(rate_raw)
            link = WifiLink(
                ssid=ssid or None,
                bssid=bssid or None,
                band=band_for_channel(channel),
                channel=channel,
                signal_percent=percent,
                # nmcli's percentage is not Windows' dBm-derived scale, but it
                # is the only strength figure available without root.
                signal_dbm=percent_to_dbm(percent),
                rx_rate_mbps=rate,
                tx_rate_mbps=rate,
            )

    return link, nearby


async def _collect_linux(include_nearby: bool) -> WifiReport:
    report = WifiReport()
    output = await run(
        ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,RATE", "dev", "wifi"],
        timeout=15.0,
    )
    if not output.strip():
        report.warnings.append(
            "Wi-Fi details need NetworkManager (nmcli), which is not available here. "
            "Wired connections report nothing under this check, which is expected."
        )
        return report

    report.link, nearby = parse_nmcli(output)
    if include_nearby:
        report.nearby = nearby
    return report


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


async def collect_wifi(include_nearby: bool = True) -> WifiReport:
    """Describe the current Wi-Fi link and, optionally, the airspace around it.

    Args:
        include_nearby: also scan for neighbouring networks so channel
            congestion can be reported. Adds a few seconds, and on some
            platforms briefly interrupts the connection while the radio sweeps
            channels, so it is worth being able to skip.

    Returns:
        A report whose ``link`` is ``None`` when the machine is on Ethernet or
        has no wireless adapter. That is a normal outcome, not a failure.
    """
    try:
        if sys.platform == "win32":
            return await _collect_windows(include_nearby)
        if sys.platform == "darwin":
            return await _collect_macos(include_nearby)
        return await _collect_linux(include_nearby)
    except Exception as exc:  # noqa: BLE001 - never let a radio query kill the server
        return WifiReport(warnings=[f"Wi-Fi check failed: {exc}"])
