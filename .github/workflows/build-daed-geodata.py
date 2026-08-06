#!/usr/bin/env python3
"""Build dae ext geodata files from dedicated daed rule lists."""

import ipaddress
import sys
from pathlib import Path


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def key(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def enc_bytes(field: int, data: bytes) -> bytes:
    return key(field, 2) + varint(len(data)) + data


def enc_string(field: int, value: str) -> bytes:
    return enc_bytes(field, value.encode())


def enc_enum(field: int, value: int) -> bytes:
    return key(field, 0) + varint(value)


def enc_msg(field: int, data: bytes) -> bytes:
    return enc_bytes(field, data)


def domain_msg(domain_type: int, value: str) -> bytes:
    return enc_enum(1, domain_type) + enc_string(2, value)


def geosite_msg(code: str, domains) -> bytes:
    return enc_string(1, code) + b"".join(enc_msg(2, domain_msg(t, v)) for t, v in domains)


def geosite_list(entries) -> bytes:
    return b"".join(enc_msg(1, geosite_msg(code, domains)) for code, domains in entries)


def cidr_msg(net) -> bytes:
    return enc_bytes(1, net.network_address.packed) + enc_enum(2, net.prefixlen)


def geoip_msg(code: str, nets) -> bytes:
    return enc_string(1, code) + b"".join(enc_msg(2, cidr_msg(net)) for net in nets)


def geoip_list(entries) -> bytes:
    return b"".join(enc_msg(1, geoip_msg(code, nets)) for code, nets in entries)


def parse_clash(text: str):
    domains = []
    nets = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        kind = parts[0].upper()
        if kind in ("IP-CIDR", "IP-CIDR6") and len(parts) >= 2:
            try:
                nets.append(ipaddress.ip_network(parts[1], strict=False))
            except ValueError:
                print(f"skip invalid CIDR: {parts[1]}", file=sys.stderr)
            continue
        if kind in ("DOMAIN-SUFFIX", "DOMAIN") and len(parts) >= 2:
            domains.append((2, parts[1]))
        elif kind == "FULL" and len(parts) >= 2:
            domains.append((3, parts[1]))
        elif kind == "DOMAIN-KEYWORD" and len(parts) >= 2:
            domains.append((0, parts[1]))
        elif "/" in line:
            try:
                nets.append(ipaddress.ip_network(parts[0], strict=False))
            except ValueError:
                print(f"skip invalid CIDR: {parts[0]}", file=sys.stderr)
        else:
            domains.append((2, parts[0]))
    return domains, nets


def main() -> int:
    if len(sys.argv) != 7:
        print("usage: build-daed-geodata.py <direct-domain.list> <direct-ip.list> <proxy-domain.list> <proxy-ip.list> <custom.dat> <custom-ip.dat>")
        return 2
    direct_domain_path, direct_ip_path, proxy_domain_path, proxy_ip_path, dat_path, ip_dat_path = map(Path, sys.argv[1:])
    direct_domains, _ = parse_clash(direct_domain_path.read_text())
    _, direct_nets = parse_clash(direct_ip_path.read_text())
    proxy_domains, _ = parse_clash(proxy_domain_path.read_text())
    _, proxy_nets = parse_clash(proxy_ip_path.read_text())
    dat_path.parent.mkdir(parents=True, exist_ok=True)
    ip_dat_path.parent.mkdir(parents=True, exist_ok=True)
    dat_path.write_bytes(geosite_list([
        ("direct", direct_domains),
        ("proxy", proxy_domains),
    ]))
    ip_dat_path.write_bytes(geoip_list([
        ("direct", direct_nets),
        ("proxy", proxy_nets),
    ]))
    print(f"built: direct_domains={len(direct_domains)} direct_ip={len(direct_nets)} proxy_domains={len(proxy_domains)} proxy_ip={len(proxy_nets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
