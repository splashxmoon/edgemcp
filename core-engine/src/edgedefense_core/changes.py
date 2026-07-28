"""Compare two scan results to answer "what changed since last time?".

All inputs are already persisted locally; this module is pure comparison logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Device, ScanResult


@dataclass
class PortChange:
    """Ports that opened or closed on one device between two scans."""

    device_id: str
    ip: str
    label: str
    opened: List[int] = field(default_factory=list)
    closed: List[int] = field(default_factory=list)


@dataclass
class ChangeReport:
    """Everything that differed between a current and previous scan."""

    current_finished_at: str
    previous_finished_at: str
    new_devices: List[Device] = field(default_factory=list)
    vanished_devices: List[Device] = field(default_factory=list)
    port_changes: List[PortChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_devices or self.vanished_devices or self.port_changes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_finished_at": self.current_finished_at,
            "previous_finished_at": self.previous_finished_at,
            "new_devices": [d.to_dict() for d in self.new_devices],
            "vanished_devices": [d.to_dict() for d in self.vanished_devices],
            "port_changes": [
                {
                    "device_id": pc.device_id,
                    "ip": pc.ip,
                    "label": pc.label,
                    "opened": pc.opened,
                    "closed": pc.closed,
                }
                for pc in self.port_changes
            ],
            "has_changes": self.has_changes,
        }


def _device_map(devices: List[Device]) -> Dict[str, Device]:
    return {d.device_id: d for d in devices}


def compare_scans(current: ScanResult, previous: ScanResult) -> ChangeReport:
    """Diff two scan results by stable device_id (MAC when available).

    Vanished devices may simply be asleep (phones, laptops) rather than gone
    from the network permanently; callers should say that in their copy.
    """
    current_map = _device_map(current.devices)
    previous_map = _device_map(previous.devices)

    current_ids = set(current_map)
    previous_ids = set(previous_map)

    new_devices = [current_map[did] for did in sorted(current_ids - previous_ids)]
    vanished_devices = [previous_map[did] for did in sorted(previous_ids - current_ids)]

    port_changes: List[PortChange] = []
    for device_id in sorted(current_ids & previous_ids):
        cur = current_map[device_id]
        prev = previous_map[device_id]
        opened = sorted(set(cur.open_ports) - set(prev.open_ports))
        closed = sorted(set(prev.open_ports) - set(cur.open_ports))
        if opened or closed:
            port_changes.append(
                PortChange(
                    device_id=device_id,
                    ip=cur.ip,
                    label=cur.label(),
                    opened=opened,
                    closed=closed,
                )
            )

    return ChangeReport(
        current_finished_at=current.finished_at,
        previous_finished_at=previous.finished_at,
        new_devices=new_devices,
        vanished_devices=vanished_devices,
        port_changes=port_changes,
    )
