# -*- coding: utf-8 -*-
from __future__ import annotations
import ipaddress
from typing import Any, Dict, Iterable, List, Tuple, Set
from ansible.utils.display import Display
display = Display()

def _ipstr(addr: str) -> str:
    if not addr:
        return addr
    if "/" in addr:
        addr = addr.split("/", 1)[0]
    return str(ipaddress.ip_address(addr))

def _is_wildcard(addr: str) -> bool:
    if addr == "*":
        return True
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_unspecified  # 0.0.0.0 or ::
    except ValueError:
        return addr in ("0.0.0.0", "::")

def normalize_tcp_listen(tcp_listen: Iterable[Dict[str, Any]], primary_ip: str) -> List[Dict[str, Any]]:
    """
    Convert Ansible tcp_listen facts to a JSON/YAML-safe list of dicts:
      [{'ip': <primary_ip>, 'protocol': 'tcp', 'port': <int>}, ...]
    Wildcard binds (0.0.0.0/::) are mapped to the host's primary_ip.
    Listens bound to other local IPs are ignored (by design).
    """
    out: List[Dict[str, Any]] = []
    p_ip = _ipstr(primary_ip)
    for entry in tcp_listen or []:
        name = entry.get("name")
        port = entry.get("port")
        addr = entry.get("address") or entry.get("ip")
        if "%" in addr:
            addr = addr.split( "%")[0]
        if addr.startswith("127.0.0") or addr == "::":
            continue
        if port is None or addr is None:
            continue
        try:
            port = int(port)
        except Exception:
           continue 
        if _is_wildcard(addr) or _ipstr(addr) == p_ip:
            out.append({"ip": p_ip, "protocol": "tcp", "port": port, "name": name})
    return out

def normalize_netbox_services(services: Iterable[Dict[str, Any]], primary_ip: str) -> List[Dict[str, Any]]:
    """
    Convert NetBox services to a list of dicts like above, filtered to this host's primary_ip and TCP only.
    NetBox 4.3.x service schema: protocol, ports[], ipaddresses[] (each has 'address' like 'A.B.C.D/nn' or '.../display')
    """
    out: List[Dict[str, Any]] = []
    p_ip = _ipstr(primary_ip)

    for svc in services or []:
        service_description = svc.get("value")
        proto = str(service_description.get("protocol").get("value")).lower()
        if proto != "tcp":
            continue
        ports = service_description.get("ports") or []
        ipas = service_description.get("ipaddresses") or []
        name = service_description.get("name")

        for port in ports:
            try:
                port = int(port)
            except Exception:
                continue
            out.append({"ip": p_ip, "protocol": "tcp", "port": port, "name": name})
    return out

def _to_tuple_set(items: Iterable[Any]) -> Set[Tuple[str, str, int, str]]:
    """
    Robustly convert a list of dicts/tuples to a set of (ip, protocol, port).
    Ignores strings (e.g., AnsibleUnsafeText) gracefully.
    """
    s: Set[Tuple[str, str, int, str]] = set()
    for x in items or []:
        try:
            if isinstance(x, dict):
                ip = _ipstr(x.get("ip") or x.get("address") or "")
                proto = str(x.get("protocol", "")).lower()
                port = int(x.get("port"))
                name = str(x.get("name"))
                if ip and proto and port is not None:
                    s.add((ip, proto, port, name))
            elif isinstance(x, (list, tuple)) and len(x) == 4:
                ip, proto, port, name = x
                ip = _ipstr(str(ip))
                proto = str(proto).lower()
                port = int(port)
                s.add((ip, proto, port, name))
            else:
                # ignore strings/unknowns
                pass
        except Exception:
            continue
    return s

def _quads_to_dicts(quads: Iterable[Tuple[str, str, int, str]]) -> List[Dict[str, Any]]:
    return [{"ip": ip, "protocol": proto, "port": int(port), "name": name} for (ip, proto, port, name) in quads]

def diff_listens(netbox_items: Iterable[Any], host_items: Iterable[Any]) -> Dict[str, Any]:
    """
    Accepts any JSON/YAML-safe sequences (lists of dicts/tuples).
    Converts to sets internally to compute:
      matched, missing_on_host, unexpected_on_host
    Returns lists of dicts (JSON/YAML friendly).
    """
    net_set = _to_tuple_set(netbox_items)
    host_set = _to_tuple_set(host_items)

    matched = sorted(list(net_set & host_set))
    missing_on_host = sorted(list(net_set - host_set))
    unexpected_on_host = sorted(list(host_set - net_set))

    display.display(str(matched))
    display.display(str(missing_on_host))
    display.display(str(unexpected_on_host))

    return {
        "matched": _quads_to_dicts(matched),
        "missing_on_host": _quads_to_dicts(missing_on_host),
        "unexpected_on_host": _quads_to_dicts(unexpected_on_host),
    }

class FilterModule(object):
    def filters(self):
        return {
            "normalize_tcp_listen": normalize_tcp_listen,
            "normalize_netbox_services": normalize_netbox_services,
            "diff_listens": diff_listens,
        }

