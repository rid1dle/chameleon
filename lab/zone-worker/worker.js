// Echo Worker for experiments E1 to E3. Deploy on a route of the test zone only.
// Returns everything Cloudflare attached to the request, so each probe records its own
// bot score, JA4, detection IDs and clearance state. Dumps all of request.cf rather than
// picking fields: the docs list different subsets in different places (research/bot-management-signals.md).
//
//   GET /echo        JSON
//   GET /echo?html=1 the same JSON inside an HTML page, so JS detections can be injected
//                    (Cloudflare injects only into HTML page views)
//   /p2/...          Phase 2 scenarios, see phase2() below
//
// Limits: challenged requests never reach the Worker (read cf-mitigated and Logpush SecurityActions
// instead), and JA3/JA4 are empty on TLS session resumption, so every probe needs a fresh handshake.

// Phase 2 scenarios under /p2/: each returns one kind of origin response, so the engine's classifier
// and transport can be checked against real Cloudflare edge behaviour. None of them is protected by a
// WAF rule (the rules match /c/ /b/ /j/ /i/ and /r/echo).
//
// Turnstile uses Cloudflare's public test keys (developers.cloudflare.com/turnstile/troubleshooting/testing/):
// they work on any hostname and need no account widget or secret.
const TURNSTILE_SITEKEYS = { pass: "1x00000000000000000000AA", block: "2x00000000000000000000AB", interactive: "3x00000000000000000000FF" };
const TURNSTILE_TEST_SECRET = "1x0000000000000000000000000000000AA"; // always passes; public test value

const text = (body, status = 200, headers = {}) =>
  new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", ...headers } });
const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store", ...headers } });

async function phase2(request, url) {
  const p = url.pathname.slice("/p2/".length);
  switch (p) {
    case "turnstile": {
      const mode = url.searchParams.get("mode") || "pass";
      const key = TURNSTILE_SITEKEYS[mode] || TURNSTILE_SITEKEYS.pass;
      return new Response(
        `<!doctype html><html><head><title>lab turnstile (${mode})</title>` +
          `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head><body>` +
          `<form method="POST" action="/p2/turnstile/verify"><div class="cf-turnstile" data-sitekey="${key}"></div>` +
          `<button type="submit">Send</button></form></body></html>`,
        { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
      );
    }
    case "turnstile/verify": {
      // The form posts cf-turnstile-response; the origin checks it with siteverify.
      if (request.method !== "POST") return text("POST the form from /p2/turnstile", 405, { allow: "POST" });
      const form = await request.formData();
      const token = form.get("cf-turnstile-response") || "";
      const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body: new URLSearchParams({ secret: TURNSTILE_TEST_SECRET, response: token }),
      });
      const v = await r.json();
      return json({ token_present: token.length > 0, token_length: token.length, siteverify: { success: v.success, error_codes: v["error-codes"] } }, v.success ? 200 : 403);
    }
    case "auth":
      return text("authentication required", 401, { "www-authenticate": 'Basic realm="cflab"' });
    case "forbidden":
      return new Response("<html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1></body></html>", {
        status: 403, headers: { "content-type": "text/html", "cache-control": "no-store" },
      });
    case "json":
      return json({ ok: true, items: [1, 2, 3] });
    case "static.css":
      return new Response("body{margin:0}\n".repeat(200), { headers: { "content-type": "text/css", "cache-control": "public, max-age=60" } });
    case "redirect":
      return Response.redirect(new URL("/echo", url).toString(), 302);
    case "redirect-loop":
      return Response.redirect(url.toString(), 302);
    case "unavailable":
      return text("maintenance", 503, { "retry-after": "120" });
    case "ratelimit-origin":
      return text("slow down", 429, { "retry-after": "30" });
    case "cookies":
      return new Response("cookies set", {
        headers: [
          ["content-type", "text/plain"], ["cache-control", "no-store"],
          ["set-cookie", "lab_session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"],
          ["set-cookie", "lab_pref=dark; Path=/p2/; Max-Age=3600"],
          ["set-cookie", "lab_quoted=\"q v\"; Path=/"],
          ["set-cookie", "lab_expired=x; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"],
        ],
      });
    case "many-headers": {
      const h = new Headers({ "content-type": "text/plain", "cache-control": "no-store" });
      for (let i = 0; i < 120; i++) h.append(`x-lab-${i}`, "v");
      return new Response("many headers", { headers: h });
    }
    case "slow": {
      const ms = Math.min(Number(url.searchParams.get("ms") || "2000"), 20000);
      await new Promise((r) => setTimeout(r, ms));
      return text(`waited ${ms} ms`);
    }
    case "cut": {
      // Sends part of a body, then errors the stream: the edge ends the response early.
      const enc = new TextEncoder();
      const stream = new ReadableStream({
        start(c) { c.enqueue(enc.encode("x".repeat(1000))); setTimeout(() => c.error(new Error("cut")), 100); },
      });
      return new Response(stream, { headers: { "content-type": "text/plain", "cache-control": "no-store" } });
    }
    case "throw":
      throw new Error("lab: uncaught exception (Cloudflare error 1101)");
    case "origin-502":
      // What a reverse proxy origin returns when its upstream fails.
      return new Response("<html><head><title>502 Bad Gateway</title></head><body><h1>Bad Gateway</h1></body></html>", {
        status: 502, headers: { "content-type": "text/html", "cache-control": "no-store" },
      });
    default:
      return text("no such scenario", 404);
  }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/p2/")) return phase2(request, url);
    const cookieNames = (request.headers.get("cookie") || "")
      .split(";").map((c) => c.split("=")[0].trim()).filter(Boolean);
    const body = {
      receivedAt: new Date().toISOString(),
      method: request.method,
      path: url.pathname,
      // Values are not echoed for cookies: only which ones arrived.
      cookieNames,
      hasClearance: cookieNames.includes("cf_clearance"),
      // Set by a Transform Rule from http.request.clearance.uuid, if one is configured.
      clearanceUuid: request.headers.get("x-lab-clearance-uuid"),
      userAgent: request.headers.get("user-agent"),
      // Header names arrive sorted; order is only measurable in lab L1.
      headers: Object.fromEntries(
        [...request.headers].filter(([k]) => k !== "cookie" && k !== "authorization")
      ),
      cf: request.cf ?? null,
    };
    const json = JSON.stringify(body, null, 2);
    if (url.searchParams.get("html") === "1") {
      const safe = json.replace(/&/g, "&amp;").replace(/</g, "&lt;");
      return new Response(
        `<!doctype html><html><head><title>lab echo</title></head><body><pre id="echo">${safe}</pre></body></html>`,
        { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
      );
    }
    return new Response(json, {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
