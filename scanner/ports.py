import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKERS = 150

COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 515: "printer", 548: "afp", 554: "rtsp", 631: "ipp",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1883: "mqtt",
    1900: "upnp", 3306: "mysql", 3389: "rdp", 5000: "upnp/http", 5432: "postgresql",
    5900: "vnc", 7000: "airplay", 8000: "http-alt", 8008: "http-alt", 8009: "chromecast",
    8080: "http-proxy", 8443: "https-alt", 9100: "jetdirect", 49152: "upnp",
    62078: "iphone-sync",
}


def service_name(port):
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


def is_open(ip, port, timeout_ms):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout_ms / 1000)
        try:
            return s.connect_ex((ip, port)) == 0
        except OSError:
            return False


def scan(ips, start, end, timeout_ms, on_open, on_host_done, on_progress, cancel):
    remaining = {ip: end - start + 1 for ip in ips}

    def task(ip, port):
        if cancel.is_set():
            return ip, port, False
        return ip, port, is_open(ip, port, timeout_ms)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [pool.submit(task, ip, port) for ip in ips for port in range(start, end + 1)]
        for future in as_completed(futures):
            ip, port, opened = future.result()
            if opened:
                on_open(ip, port, service_name(port))
            remaining[ip] -= 1
            if remaining[ip] == 0:
                on_host_done(ip)
            on_progress()
