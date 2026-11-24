# L2 results: JS environment, FlareSolverr vs headful Chromium (2026-11-24)

Page: `lab/l2/probe.html`, served over HTTPS as `probe.lab.test` on the `cflab` network. It reads 32 properties a challenge script can see and writes them into the page. Captures: `flaresolverr-chrome.json` (FlareSolverr 3.5.2 default, `request.get`) and `chromium-headful.json` (same image's Chromium under Xvfb, no driver).

## Differences (6 of 32)

| Property | Headful baseline | FlareSolverr | Signal |
|---|---|---|---|
| `navigator.languages` | `["en-US","en"]` | `["C.UTF-8"]` | Not a real locale. Same cause as L1-2 (`LANG` passed to `--accept-lang`) |
| `screen` | 1280x1024 (the Xvfb display) | **800x600** | Headless default virtual screen |
| `outerWidth x outerHeight` | 1050x1004 | **1920x1080** | Window **larger than the screen**, from `--window-size=1920,1080`. Impossible on a real display; a one-line check |
| `document.hasFocus()` | true | false | The page never has focus |
| WebGL renderer | none (no WebGL under Xvfb) | `ANGLE (... SwiftShader ...)` | Software renderer. Common on servers and VMs, so weak alone |

## Same in both (26 of 32)

`navigator.webdriver` (false), `'webdriver' in navigator`, the prototype and descriptor checks on `navigator`, `maxTouchPoints` (0), `connection.rtt` (100), `window.chrome` keys (`app, csi, loadTimes`), `userAgentData` brands, plugins (5), `pdfViewerEnabled`, notification permission (`default` / `prompt`), UA, platform, timezone, `visibilityState`.

## Findings

| # | Finding | Evidence |
|---|---|---|
| L2-1 | **FlareSolverr's JS cover-up patches never run in the default setup.** `undetected_chromedriver` starts Chrome itself and attaches chromedriver through `--remote-debugging-port`, so Chrome never gets `--enable-automation` and `navigator.webdriver` is already false. The patches (`Proxy` on `navigator`, `maxTouchPoints = 1`) are guarded by `if navigator.webdriver`, so they are skipped. Source alone suggested they ran; the run shows they do not. | `src/undetected_chromedriver/dprocess.py:18-61`, `__init__.py:276-283`, `:504`; captured values |
| L2-2 | **The classic headless tells are gone in headless `new`.** Plugins, `window.chrome`, permissions consistency and `userAgentData` all match the headful build. | 26 matching properties |
| L2-3 | **What is left is configuration, not engine:** locale (`C.UTF-8`), geometry (window bigger than screen), focus, and the software GPU. Each comes from a FlareSolverr default (`LANG` from the base image, `--window-size`, headless screen size), so an operator could fix each one. They identify **default deployments**, not the technique. | Table |

## Limits

- The baseline also runs under Xvfb in a container, so it is not a real desktop. It lacks WebGL, and its screen is the Xvfb size. Use it to separate "headless" from "headful", not "bot" from "human".
- One run each. All values are deterministic for a given image and flags except `connection.rtt`, which Chrome rounds and could vary.
- No mouse, keyboard or timing data. Behaviour (F3) can only be seen against a real challenge, in E2.
