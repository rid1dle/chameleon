"""Scrub and check every committable Phase 2 file (this repo is public).

  python3 -I scripts/phase2/scrub.py --fix     rewrite files in place
  python3 -I scripts/phase2/scrub.py --check   exit 1 listing every remaining hit

Files: everything under experiments/test-results/P2 that git would commit (tracked or not ignored),
so raw records (gitignored) are left alone. Same rules as E4's scrub (scripts/zone/e4_capture.sh),
made precise enough not to damage measurements:

  - IPv4 addresses -> <removed>. A dotted quad right after a letter and "/" is a version
    (Chrome/152.0.0.0), not an address, and is kept; one after "//" (a URL host) is scrubbed.
  - Token-like runs of 40+ characters -> <removed>: they must contain a letter and a digit and not be
    pure hex. Pure hex is a public hash (certificate SHA-256, JA3 MD5); digit-and-dash runs are JA3
    and cipher lists.
  - The data-centre suffix of a cf-ray (16 hex then -ABC) -> -<removed>: it says where the client is.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
P2 = "experiments/test-results/P2"

IPV4 = re.compile(r"(?<![\w.])(?<![A-Za-z]/)(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
TOKEN = re.compile(r"[A-Za-z0-9_.~%+=-]{40,}")
CF_RAY = re.compile(r"\b([0-9a-f]{16})-([A-Z]{3})\b")


def is_secret_like(run: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]+", run):
        return False
    return bool(re.search(r"[A-Za-z]", run)) and bool(re.search(r"\d", run))


def files():
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", P2],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()
    return [ROOT / f for f in out if (ROOT / f).is_file()]


def scrub(text: str) -> str:
    text = IPV4.sub("<removed>", text)
    text = TOKEN.sub(lambda m: "<removed>" if is_secret_like(m.group(0)) else m.group(0), text)
    return CF_RAY.sub(lambda m: f"{m.group(1)}-<removed>", text)


def hits(text: str):
    found = [("ipv4", m.group(0)) for m in IPV4.finditer(text)]
    found += [("token", m.group(0)[:24] + "...") for m in TOKEN.finditer(text) if is_secret_like(m.group(0))]
    found += [("cf-ray suffix", m.group(0)) for m in CF_RAY.finditer(text)]
    return found


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    bad = 0
    for f in files():
        try:
            text = f.read_text()
        except UnicodeDecodeError:
            continue
        if mode == "--fix":
            new = scrub(text)
            if new != text:
                f.write_text(new)
                print(f"scrubbed {f.relative_to(ROOT)}")
        for kind, value in hits(f.read_text()):
            bad += 1
            print(f"{f.relative_to(ROOT)}: {kind}: {value}")
    if bad:
        print(f"scrub check failed: {bad} hit(s)", file=sys.stderr)
        sys.exit(1)
    print(f"scrub check passed: {len(files())} files")


if __name__ == "__main__":
    main()
