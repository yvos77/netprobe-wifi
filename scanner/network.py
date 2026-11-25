import ipaddress
import socket

MAX_HOSTS = 1022


def local_ip():
    for target in ("8.8.8.8", "1.1.1.1", "10.255.255.255"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target, 80))
                ip = s.getsockname()[0]
            if not ip.startswith("127."):
                return ip
        except OSError:
            continue
    return "127.0.0.1"


def default_network():
    return str(ipaddress.ip_network(f"{local_ip()}/24", strict=False))


def parse_network(text):
    try:
        network = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        raise ValueError("Rede inválida. Use o formato 192.168.0.0/24.")
    if network.version != 4:
        raise ValueError("Apenas redes IPv4 são suportadas.")
    if network.prefixlen > 30:
        raise ValueError("Use uma rede de /22 a /30.")
    if network.num_addresses - 2 > MAX_HOSTS:
        raise ValueError(f"Rede grande demais (máximo de {MAX_HOSTS} hosts, ou seja, /22).")
    return network


def host_list(network):
    return [str(host) for host in network.hosts()]


def source_ip_for(network):
    first_host = str(next(network.hosts()))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((first_host, 9))
            ip = s.getsockname()[0]
    except OSError:
        return None
    return ip if ipaddress.ip_address(ip) in network else None


def ip_sort_key(ip):
    return int(ipaddress.ip_address(ip))
