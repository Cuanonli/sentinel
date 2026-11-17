// Sentinel — wallet & transaction guard. Vercel serverless entry.
// Same shared core as the local server (lib/sentinel.mjs), exposed as
// POST /api/guard (GET returns service info + rule summary).
//
// Vercel specifics:
//  - bodyParser is OFF: the raw request stream is read so an optional
//    HMAC signature (x-sentinel-signature) can be verified over the raw
//    body, exactly like the Gatekeeper agent's pattern.
//  - HMAC is OPTIONAL here: Sentinel is a public demo endpoint. If
//    SENTINEL_HMAC_SECRET is set and a signature header is present, it
//    must verify (else 401); unsigned requests are served as public.
//  - Hobby plan maxDuration is 10s, so the fail-closed guard fires at 8s
//    (verdicts normally take 0.2–2s; the guard is only a safety net).
//  - The proving artifacts (sentinel.wasm + sentinel_final.zkey + vk.json)
//    are small and ship in the bundle via vercel.json includeFiles.
//  - Secrets come from Vercel env vars only (SENTINEL_HMAC_SECRET).
//    Never commit a real value.

import { createCore, resolveArtifactDir } from "../lib/sentinel.mjs";

export const config = { api: { bodyParser: false } };

const HMAC_SECRET = process.env.SENTINEL_HMAC_SECRET || "";

const core = createCore({
  hmacSecret: HMAC_SECRET,
  artifactDir: resolveArtifactDir(),
});

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(core.handleGet()));
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "method not allowed" }));
    return;
  }

  let raw;
  try {
    raw = await readRaw(req);
  } catch {
    try { res.writeHead(400); res.end(); } catch {}
    return;
  }

  // Optional HMAC: a present-but-invalid signature is rejected; unsigned
  // requests are served as public (authenticated: false in the response).
  const sigHeader = req.headers["x-sentinel-signature"];
  let authenticated = false;
  if (HMAC_SECRET && sigHeader) {
    if (!core.verifyHmac(raw, sigHeader)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "bad signature" }));
      return;
    }
    authenticated = true;
  }

  let body;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "invalid json" }));
    return;
  }

  // 8s safety net (Hobby maxDuration is 10s): fail closed, never hang.
  let responded = false;
  const timer = setTimeout(() => {
    if (responded) return;
    responded = true;
    try {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        service: "sentinel",
        verdict: "REVIEW",
        reason_codes: ["RPC_ERROR"],
        error: "guard timed out while reading on-chain facts",
        checks: [{ name: "timeout_guard", outcome: "unknown", detail: "8s guard fired" }],
        facts: null,
        proof: null,
        proof_omitted: "request timed out — no complete fact set, so no proof applies",
        authenticated,
      }));
    } catch {}
  }, 8000);

  try {
    const out = await core.handleRequest(body, { authenticated });
    if (responded) return;
    responded = true;
    clearTimeout(timer);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(out));
  } catch (e) {
    console.log(`[sentinel] handler error: ${String(e).slice(0, 200)}`);
    if (responded) return;
    responded = true;
    clearTimeout(timer);
    try {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        service: "sentinel",
        verdict: "REVIEW",
        reason_codes: ["RPC_ERROR"],
        error: "internal error while screening",
        checks: [],
        facts: null,
        proof: null,
        proof_omitted: "internal error — no complete fact set, so no proof applies",
        authenticated,
      }));
    } catch {}
  }
}
