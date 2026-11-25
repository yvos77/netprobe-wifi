import platform
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

SYSTEM = platform.system()
WORKERS = 64

TTL_RE = re.compile(r"ttl[=:]\s*(\d+)", re.IGNORECASE)
TIME_RE = re.compile(r"(?:time|tempo)\s*[=<]\s*([\d.,]+)\s*ms", re.IGNORECASE)


def ping_command(ip, timeout_ms):
    if SYSTEM == "Windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if SYSTEM == "Darwin":
        return ["ping", "-n", "-c", "1", "-W", str(timeout_ms), ip]
    return ["ping", "-n", "-c", "1", "-W", f"{timeout_ms / 1000:.2f}", ip]


def ping(ip, timeout_ms):
    extra = {"creationflags": subprocess.CREATE_NO_WINDOW} if SYSTEM == "Windows" else {}
    try:
        result = subprocess.run(
            ping_command(ip, timeout_ms),
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=timeout_ms / 1000 + 2,
            **extra,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    ttl = TTL_RE.search(result.stdout)
    if not ttl:
        return None
    latency = TIME_RE.search(result.stdout)
    return {
        "ttl": int(ttl.group(1)),
        "latency_ms": float(latency.group(1).replace(",", ".")) if latency else None,
    }


def sweep(ips, timeout_ms, on_result, cancel):
    def task(ip):
        if cancel.is_set():
            return None
        return ping(ip, timeout_ms)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(task, ip): ip for ip in ips}
        for future in as_completed(futures):
            on_result(futures[future], future.result())
