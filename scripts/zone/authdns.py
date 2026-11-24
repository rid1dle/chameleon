"""Ask a zone's authoritative nameserver directly, bypassing resolver caches.

After scripts/zone/down.sh, public resolvers cache NXDOMAIN for the zone's negative TTL (SOA minimum,
1800 s on riddlelab.dev), so a check through 1.1.1.1 can say "does not exist" for 30 minutes after
up.sh has recreated the record. The authoritative answer is current.

Routing follows cfprobe's: with CFPROBE_PROXY set (http://, https://, socks5://, socks5h://), every
query goes through that proxy over TCP (DoH over HTTPS, and DNS over TCP to the nameserver); without
it, queries are direct (UDP to the nameserver), as before proxies existed.

Usage: python3 -I authdns.py <hostname> [A|AAAA]
Prints the status (NOERROR or NXDOMAIN) on the first line, then one address per line.
Exit code: 0 NOERROR with addresses, 3 NXDOMAIN, 1 anything else.
"""
import base64
import json
import os
import random
import socket
import ssl
import struct
import sys
import urllib.parse
import urllib.request

PROXY = os.environ.get("CFPROBE_PROXY", "").strip()


def tunnel(host, port):
    """A TCP connection to host:port through CFPROBE_PROXY. The host name goes to the proxy."""
    u = urllib.parse.urlsplit(PROXY)
    default = {"http": 8080, "https": 443, "socks5": 1080, "socks5h": 1080}
    if u.scheme not in default:
        sys.exit(f"CFPROBE_PROXY scheme {u.scheme!r} is not supported")
    s = socket.create_connection((u.hostname, u.port or default[u.scheme]), timeout=10)
    user = urllib.parse.unquote(u.username or "")
    pw = urllib.parse.unquote(u.password or "")
    if u.scheme in ("http", "https"):
        if u.scheme == "https":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if user:
            req += "Proxy-Authorization: Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() + "\r\n"
        s.sendall((req + "\r\n").encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            b = s.recv(1)
            if not b:
                sys.exit("proxy closed the connection during CONNECT")
            head += b
        status = head.split(b" ", 2)[1]
        if not status.startswith(b"2"):
            sys.exit(f"proxy refused CONNECT {host}:{port}: {status.decode()}")
        return s
    s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
    method = s.recv(2)[1]
    if method == 2:
        s.sendall(bytes([1, len(user)]) + user.encode() + bytes([len(pw)]) + pw.encode())
        if s.recv(2)[1] != 0:
            sys.exit("proxy refused the credentials")
    elif method != 0:
        sys.exit("proxy offered no usable authentication method")
    try:
        addr = b"\x01" + socket.inet_aton(host)
    except OSError:
        addr = b"\x03" + bytes([len(host)]) + host.encode()
    s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    r = s.recv(4)
    if r[1] != 0:
        sys.exit(f"proxy could not reach {host}:{port} (SOCKS5 reply {r[1]})")
    s.recv({1: 4, 4: 16}.get(r[3], 0) + 2 if r[3] != 3 else s.recv(1)[0] + 2)
    return s

DOH = "https://cloudflare-dns.com/dns-query"
TYPES = {"A": 1, "AAAA": 28, "NS": 2}


def doh(name, qtype):
    if PROXY:
        host = urllib.parse.urlsplit(DOH).hostname
        s = ssl.create_default_context().wrap_socket(tunnel(host, 443), server_hostname=host)
        s.sendall(f"GET /dns-query?name={name}&type={qtype} HTTP/1.1\r\nHost: {host}\r\naccept: application/dns-json\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while chunk := s.recv(65536):
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        if b"chunked" in head.lower():
            out, rest = b"", body
            while rest:
                size_line, _, rest = rest.partition(b"\r\n")
                n = int(size_line.split(b";")[0], 16)
                if n == 0:
                    break
                out, rest = out + rest[:n], rest[n + 2:]
            body = out
        return json.loads(body)
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
    if PROXY:
        # DNS over TCP (RFC 1035 4.2.2) inside the proxy tunnel: UDP cannot go through it.
        s = tunnel(server, 53)
        s.sendall(struct.pack(">H", len(q)) + q)
        want = struct.unpack(">H", s.recv(2))[0]
        r = b""
        while len(r) < want:
            r += s.recv(want - len(r))
    else:
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
