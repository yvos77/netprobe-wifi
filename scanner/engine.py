import threading
import time
import traceback
from dataclasses import asdict, dataclass

from . import icmp, ports
from .arp import ArpProber, read_arp_cache
from .inventory import Inventory
from .network import host_list, parse_network, source_ip_for

PHASE_LABELS = {
    "parado": "Pronto para iniciar",
    "icmp": "Varredura ICMP (ping sweep)",
    "arp": "ARP Probe nos IPs sem resposta ao ping",
    "vinculacao": "Vinculação IP/MAC dos hosts que responderam ao ping",
    "portas": "Varredura de portas TCP",
    "aguardando": "Monitorando — aguardando próximo ciclo",
    "concluido": "Varredura concluída",
    "cancelado": "Varredura interrompida",
    "erro": "Erro durante a varredura",
}


@dataclass
class ScanConfig:
    network: str
    icmp_timeout_ms: int
    arp_timeout_ms: int
    port_start: int
    port_end: int
    port_timeout_ms: int
    monitor: bool
    interval_s: int

    @classmethod
    def from_dict(cls, data):
        def integer(key, low, high, label):
            try:
                value = int(data.get(key))
            except (TypeError, ValueError):
                raise ValueError(f"{label}: informe um número inteiro.")
            if not low <= value <= high:
                raise ValueError(f"{label}: use um valor entre {low} e {high}.")
            return value

        network = parse_network(data.get("network", ""))
        config = cls(
            network=str(network),
            icmp_timeout_ms=integer("icmp_timeout_ms", 100, 10000, "Timeout ICMP"),
            arp_timeout_ms=integer("arp_timeout_ms", 200, 10000, "Timeout ARP"),
            port_start=integer("port_start", 1, 65535, "Porta inicial"),
            port_end=integer("port_end", 1, 65535, "Porta final"),
            port_timeout_ms=integer("port_timeout_ms", 50, 5000, "Timeout de porta"),
            monitor=bool(data.get("monitor", False)),
            interval_s=integer("interval_s", 5, 3600, "Intervalo do monitoramento"),
        )
        if config.port_start > config.port_end:
            raise ValueError("A porta inicial deve ser menor ou igual à porta final.")
        return config


class ScanEngine:
    def __init__(self):
        self.inventory = Inventory()
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread = None
        self._prober = None
        self._config = None
        self._state = self._initial_state()

    @staticmethod
    def _initial_state():
        return {
            "running": False,
            "phase": "parado",
            "done": 0,
            "total": 0,
            "cycle": 0,
            "error": None,
            "timings": {},
            "arp_mode": None,
            "self_ip": None,
            "started_at": None,
            "finished_at": None,
            "next_cycle_at": None,
        }

    def _set(self, **changes):
        with self._lock:
            self._state.update(changes)

    def _advance(self):
        with self._lock:
            self._state["done"] += 1

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, data):
        config = ScanConfig.from_dict(data)
        if self.running:
            raise RuntimeError("Já existe uma varredura em andamento.")

        network = parse_network(config.network)
        self._config = config
        self._prober = ArpProber(network)
        self_ip = source_ip_for(network)
        self.inventory.reset(host_list(network), self_ip, self._prober.own_mac)
        self._cancel.clear()

        with self._lock:
            self._state = self._initial_state()
            self._state.update(
                running=True,
                arp_mode=self._prober.description,
                self_ip=self_ip,
                started_at=time.time(),
            )

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._cancel.set()

    def _run(self):
        try:
            while True:
                self._cycle()
                if self._cancel.is_set() or not self._config.monitor:
                    break
                self._set(phase="aguardando", next_cycle_at=time.time() + self._config.interval_s)
                if self._cancel.wait(self._config.interval_s):
                    break
            self._set(phase="cancelado" if self._cancel.is_set() else "concluido")
        except Exception as exc:
            traceback.print_exc()
            self._set(phase="erro", error=f"{type(exc).__name__}: {exc}")
        finally:
            self._set(running=False, finished_at=time.time(), next_cycle_at=None)

    def _phase(self, name, total, action):
        if self._cancel.is_set():
            return
        self._set(phase=name, done=0, total=total)
        started = time.perf_counter()
        action()
        with self._lock:
            self._state["timings"][name] = round(time.perf_counter() - started, 2)

    def _cycle(self):
        config = self._config
        inventory = self.inventory
        hosts = host_list(parse_network(config.network))
        self_ip = self._state["self_ip"]

        with self._lock:
            self._state["cycle"] += 1
            self._state["timings"] = {}
        inventory.begin_cycle()

        def run_icmp():
            def on_result(ip, result):
                if result:
                    inventory.record_icmp(ip, result["latency_ms"], result["ttl"])
                self._advance()
            icmp.sweep(hosts, config.icmp_timeout_ms, on_result, self._cancel)
        self._phase("icmp", len(hosts), run_icmp)

        silent = [ip for ip in inventory.silent_hosts() if ip != self_ip]

        def run_arp_probe():
            found = self._prober.probe(silent, config.arp_timeout_ms, self._cancel)
            for ip, entry in found.items():
                inventory.record_arp(ip, entry["macs"], entry["latency_ms"], discovered=True)
            self._set(done=len(silent))
        self._phase("arp", len(silent), run_arp_probe)

        if self._cancel.is_set():
            return
        inventory.close_presence()

        responders = [ip for ip in inventory.icmp_responders() if ip != self_ip]

        def run_binding():
            found = self._prober.probe(responders, config.arp_timeout_ms, self._cancel)
            for ip, entry in found.items():
                inventory.record_arp(ip, entry["macs"], entry["latency_ms"], discovered=False)
            missing = inventory.missing_mac()
            if missing:
                cache = read_arp_cache()
                for ip in missing:
                    if ip in cache:
                        inventory.record_cached_mac(ip, cache[ip])
            self._set(done=len(responders))
        self._phase("vinculacao", len(responders), run_binding)

        port_range = (config.port_start, config.port_end)
        targets = inventory.needs_port_scan(port_range)

        def run_ports():
            inventory.ports_begin(targets, port_range)
            ports.scan(
                targets,
                config.port_start,
                config.port_end,
                config.port_timeout_ms,
                on_open=inventory.ports_add,
                on_host_done=inventory.ports_done,
                on_progress=self._advance,
                cancel=self._cancel,
            )
        self._phase("portas", len(targets) * (config.port_end - config.port_start + 1), run_ports)

    def snapshot(self):
        with self._lock:
            state = dict(self._state)
            state["timings"] = dict(self._state["timings"])
        state["phase_label"] = PHASE_LABELS[state["phase"]]
        state["config"] = asdict(self._config) if self._config else None
        state.update(self.inventory.snapshot())
        return state
