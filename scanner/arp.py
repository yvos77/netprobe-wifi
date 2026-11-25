import logging
import platform
import re
import shutil
import socket
import subprocess
import time
import uuid

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, conf, get_if_hwaddr, srp
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

SYSTEM = platform.system()
RETRIES = 2
SEND_INTERVAL_S = 0.002

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAC_RE = re.compile(r"\b([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})\b", re.IGNORECASE)
IGNORED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def normalize_mac(mac):
    return ":".join(part.zfill(2) for part in re.split(r"[:-]", mac.lower()))


def read_arp_cache():
    if SYSTEM == "Linux" and shutil.which("ip"):
        command = ["ip", "neigh", "show"]
    elif SYSTEM == "Windows":
        command = ["arp", "-a"]
    else:
        command = ["arp", "-an"]

    try:
        output = subprocess.run(command, capture_output=True, text=True, errors="ignore", timeout=10).stdout
    except (subprocess.TimeoutExpired, OSError):
        return {}

    table = {}
    for line in output.splitlines():
        if "FAILED" in line.upper() or "INCOMPLETE" in line.upper():
            continue
        ip, mac = IP_RE.search(line), MAC_RE.search(line)
        if not ip or not mac:
            continue
        mac = normalize_mac(mac.group(1))
        if mac in IGNORED_MACS or mac.startswith("01:00:5e"):
            continue
        table[ip.group(1)] = mac
    return table


class ArpProber:
    def __init__(self, network):
        self.mode = "cache"
        self.iface = None
        self.own_mac = None

        if SCAPY_AVAILABLE:
            try:
                conf.route.resync()
                self.iface = conf.route.route(str(next(network.hosts())))[0]
                self.own_mac = get_if_hwaddr(self.iface).lower()
                conf.L2socket(iface=self.iface).close()
                self.mode = "scapy"
            except Exception:
                pass

        if self.own_mac is None:
            node = f"{uuid.getnode():012x}"
            self.own_mac = ":".join(node[i:i + 2] for i in range(0, 12, 2))

    @property
    def description(self):
        if self.mode == "scapy":
            return "ARP Request montado com Scapy (camada 2)"
        return "Cache ARP do sistema (execute como administrador/root para ARP direto)"

    def probe(self, ips, timeout_ms, cancel):
        if not ips:
            return {}
        if self.mode == "scapy":
            return self._probe_scapy(ips, timeout_ms, cancel)
        return self._probe_cache(ips, timeout_ms, cancel)

    def _probe_scapy(self, ips, timeout_ms, cancel):
        results = {}
        pending = list(ips)
        for _ in range(RETRIES):
            if not pending or cancel.is_set():
                break
            packets = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip) for ip in pending]
            answered, _ = srp(
                packets,
                iface=self.iface,
                timeout=timeout_ms / 1000,
                inter=SEND_INTERVAL_S,
                multi=True,
                verbose=False,
            )
            for sent, reply in answered:
                ip = reply[ARP].psrc
                entry = results.setdefault(ip, {"macs": [], "latency_ms": None})
                mac = reply[ARP].hwsrc.lower()
                if mac not in entry["macs"]:
                    entry["macs"].append(mac)
                if entry["latency_ms"] is None:
                    entry["latency_ms"] = round((reply.time - sent.sent_time) * 1000, 2)
            pending = [ip for ip in pending if ip not in results]
        return results

    def _probe_cache(self, ips, timeout_ms, cancel):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for ip in ips:
                if cancel.is_set():
                    break
                try:
                    s.sendto(b"", (ip, 9))
                except OSError:
                    pass
        time.sleep(timeout_ms / 1000)
        table = read_arp_cache()
        return {ip: {"macs": [table[ip]], "latency_ms": None} for ip in ips if ip in table}
