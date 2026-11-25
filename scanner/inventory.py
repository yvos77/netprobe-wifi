import threading
import time
from dataclasses import dataclass, field

from .network import ip_sort_key


@dataclass
class Device:
    ip: str
    status: str = "livre"
    method: str | None = None
    macs: list = field(default_factory=list)
    latency_ms: float | None = None
    ttl: int | None = None
    ports: list = field(default_factory=list)
    ports_state: str = "pendente"
    ports_range: tuple | None = None
    is_self: bool = False
    last_seen: float | None = None
    seen_in_cycle: bool = False

    @property
    def conflict(self):
        return len(self.macs) > 1

    def to_dict(self):
        return {
            "ip": self.ip,
            "status": self.status,
            "method": self.method,
            "macs": self.macs,
            "conflict": self.conflict,
            "latency_ms": self.latency_ms,
            "ttl": self.ttl,
            "ports": self.ports,
            "ports_state": self.ports_state,
            "is_self": self.is_self,
            "last_seen": self.last_seen,
        }


class Inventory:
    def __init__(self):
        self._lock = threading.Lock()
        self._devices = {}

    def reset(self, ips, self_ip=None, self_mac=None):
        with self._lock:
            self._devices = {ip: Device(ip) for ip in ips}
            if self_ip in self._devices:
                device = self._devices[self_ip]
                device.is_self = True
                device.macs = [self_mac] if self_mac else []

    def begin_cycle(self):
        with self._lock:
            for device in self._devices.values():
                device.seen_in_cycle = False

    def _mark_seen(self, device, method):
        device.status = "online"
        device.method = method
        device.seen_in_cycle = True
        device.last_seen = time.time()

    def record_icmp(self, ip, latency_ms, ttl):
        with self._lock:
            device = self._devices[ip]
            self._mark_seen(device, "ICMP")
            device.latency_ms = latency_ms
            device.ttl = ttl

    def record_arp(self, ip, macs, latency_ms, discovered):
        with self._lock:
            device = self._devices[ip]
            if device.is_self:
                return
            device.macs = list(macs)
            if discovered:
                self._mark_seen(device, "ARP")
                device.latency_ms = latency_ms
                device.ttl = None

    def record_cached_mac(self, ip, mac):
        with self._lock:
            device = self._devices[ip]
            if not device.macs:
                device.macs = [mac]

    def close_presence(self):
        with self._lock:
            for device in self._devices.values():
                if device.seen_in_cycle:
                    continue
                device.status = "offline" if device.last_seen else "livre"
                device.latency_ms = None
                device.ttl = None
                device.ports = []
                device.ports_state = "pendente"
                device.ports_range = None

    def ips_by(self, predicate):
        with self._lock:
            return sorted((d.ip for d in self._devices.values() if predicate(d)), key=ip_sort_key)

    def icmp_responders(self):
        return self.ips_by(lambda d: d.seen_in_cycle and d.method == "ICMP")

    def silent_hosts(self):
        return self.ips_by(lambda d: not d.seen_in_cycle)

    def missing_mac(self):
        return self.ips_by(lambda d: d.seen_in_cycle and not d.macs)

    def needs_port_scan(self, port_range):
        return self.ips_by(lambda d: d.seen_in_cycle and d.ports_range != port_range)

    def ports_begin(self, ips, port_range):
        with self._lock:
            for ip in ips:
                device = self._devices[ip]
                device.ports = []
                device.ports_state = "varrendo"
                device.ports_range = port_range

    def ports_add(self, ip, port, service):
        with self._lock:
            ports = self._devices[ip].ports
            ports.append({"port": port, "service": service})
            ports.sort(key=lambda p: p["port"])

    def ports_done(self, ip):
        with self._lock:
            self._devices[ip].ports_state = "concluido"

    def snapshot(self):
        with self._lock:
            devices = sorted(self._devices.values(), key=lambda d: ip_sort_key(d.ip))
            rows = [d.to_dict() for d in devices]
        online = [r for r in rows if r["status"] == "online"]
        return {
            "devices": rows,
            "summary": {
                "total": len(rows),
                "online": len(online),
                "icmp": sum(1 for r in online if r["method"] == "ICMP"),
                "arp": sum(1 for r in online if r["method"] == "ARP"),
                "offline": sum(1 for r in rows if r["status"] == "offline"),
                "free": sum(1 for r in rows if r["status"] == "livre"),
                "conflicts": sum(1 for r in rows if r["conflict"]),
                "open_ports": sum(len(r["ports"]) for r in rows),
            },
        }
