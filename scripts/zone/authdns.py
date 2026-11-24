"""Ask a zone's authoritative nameserver directly, bypassing resolver caches.

After scripts/zone/down.sh, public resolvers cache NXDOMAIN for the zone's negative TTL (SOA minimum,
1800 s on riddlelab.dev), so a check through 1.1.1.1 can say "does not exist" for 30 minutes after
up.sh has recreated the record. The authoritative answer is current.

Usage: python3 -I authdns.py <hostname> [A|AAAA]
Prints the status (NOERROR or NXDOMAIN) on the first line, then one address per line.
Exit code: 0 NOERROR with addresses, 3 NXDOMAIN, 1 anything else.
"""
import json
import random
import socket
import struct
import sys
import urllib.request

DOH = "https://cloudflare-dns.com/dns-query"
TYPES = {"A": 1, "AAAA": 28, "NS": 2}


def doh(name, qtype):
    req = urllib.request.Request(f"{DOH}?name={name}&type={qtype}", headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def nameserver_ip(host):
    """Walk up the labels until one has NS records, then return the first NS's IPv4 address."""
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        ans = [a["data"] for a in doh(".".join(labels[i:]), "NS").get("Answer", []) if a["type"] == 2]
        if ans:
            ns = ans[0].rstrip(".")
            ips = [a["data"] for a in doh(ns, "A").get("Answer", []) if a["type"] == 1]
            if ips:
                return ns, ips[0]
    sys.exit(f"no nameserver found for {host}")


def skip_name(buf, i):
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def query(server, host, qtype):
    tid = random.randrange(65536)
    q = struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in host.split(".")) + b"\0"
    q += struct.pack(">HH", TYPES[qtype], 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, (server, 53))
    r, _ = s.recvfrom(4096)
    rcode, count = r[3] & 0xF, struct.unpack(">H", r[6:8])[0]
    i = skip_name(r, 12) + 4
    out = []
    for _ in range(count):
        i = skip_name(r, i)
        t, _, _, length = struct.unpack(">HHIH", r[i:i + 10])
        i += 10
        data = r[i:i + length]
        i += length
        if t == 1:
            out.append(socket.inet_ntop(socket.AF_INET, data))
        elif t == 28:
            out.append(socket.inet_ntop(socket.AF_INET6, data))
    return rcode, out


def main():
    host = sys.argv[1]
    qtype = sys.argv[2] if len(sys.argv) > 2 else "A"
    _, ip = nameserver_ip(host)
    rcode, addrs = query(ip, host, qtype)
    print({0: "NOERROR", 3: "NXDOMAIN"}.get(rcode, f"RCODE{rcode}"))
    for a in addrs:
        print(a)
    sys.exit(0 if rcode == 0 and addrs else 3 if rcode == 3 else 1)


if __name__ == "__main__":
    main()
