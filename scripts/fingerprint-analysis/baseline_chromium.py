"""Headful Chromium baseline for L1: no chromedriver, no stealth patches, no UA override.

Runs inside the FlareSolverr image (same Chromium build) under Xvfb. Chromium opens the URL itself;
CDP is attached only after the load to read the page text, which does not change what was sent
on the wire. Usage (inside the container): xvfb-run -a python3 baseline_chromium.py <url>
"""
import asyncio
import json
import subprocess
import sys
import time
import urllib.request

import websockets

URL = sys.argv[1]
PORT = 9333

proc = subprocess.Popen([
    "chromium", "--no-sandbox", "--no-first-run", "--no-default-browser-check",
    "--ignore-certificate-errors", f"--remote-debugging-port={PORT}",
    "--user-data-dir=/tmp/baseline-profile", URL,
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(8)
    targets = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json"))
    page = next(t for t in targets if t["type"] == "page" and t["url"].startswith(URL))

    async def read_body():
        async with websockets.connect(page["webSocketDebuggerUrl"], max_size=None) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate",
                                      "params": {"expression": "document.body.innerText", "returnByValue": True}}))
            return json.loads(await ws.recv())["result"]["result"]["value"]

    print(asyncio.run(read_body()))
finally:
    proc.terminate()
