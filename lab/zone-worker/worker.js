// Echo Worker for experiments E1 to E3. Deploy on a route of the test zone only.
// Returns everything Cloudflare attached to the request, so each probe records its own
// bot score, JA4, detection IDs and clearance state. Dumps all of request.cf rather than
// picking fields: the docs list different subsets in different places (research/bot-management-signals.md).
//
//   GET /echo        JSON
//   GET /echo?html=1 the same JSON inside an HTML page, so JS detections can be injected
//                    (Cloudflare injects only into HTML page views)
//
// Limits: challenged requests never reach the Worker (read cf-mitigated and Logpush SecurityActions
// instead), and JA3/JA4 are empty on TLS session resumption, so every probe needs a fresh handshake.

export default {
  async fetch(request) {
    const url = new URL(request.url);
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
