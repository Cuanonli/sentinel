// Sentinel — wallet & transaction guard.
// Local server: Node.js stdlib HTTP + shared core (lib/sentinel.mjs),
// serving the demo page (public/) and the same POST /api/guard as the
// Vercel serverless entry (api/guard.js).
//
// Run:  npm start          (listens on http://127.0.0.1:3000)
//       PORT=3001 npm start
//
// No secrets are required. Set SENTINEL_HMAC_SECRET to enable optional
// HMAC verification of signed requests (see lib/sentinel.mjs).

import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync, existsSync } from "node:fs";
import { createCore, resolveArtifactDir } from "./lib/sentinel.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "public");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "127.0.0.1";
const HMAC_SECRET = process.env.SENTINEL_HMAC_SECRET || "";

const core = createCore({
  hmacSecret: HMAC_SECRET,
  artifactDir: resolveArtifactDir(),
});

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

function serveStatic(req, res) {
  const urlPath = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  const safe = path.normalize(urlPath).replace(/^(\.\.[\/\\])+/, "");
  const file = path.join(PUBLIC_DIR, safe);
  if (!file.startsWith(PUBLIC_DIR) || !existsSync(file)) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
    return;
  }
  const ext = path.extname(file);
  res.writeHead(200, { "content-type": MIME[ext] || "application/octet-stream" });
  res.end(readFileSync(file));
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/api/guard") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(core.handleGet()));
    return;
  }
  if (req.method === "GET") {
    serveStatic(req, res);
    return;
  }
  if (req.method !== "POST" || req.url !== "/api/guard") {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
    return;
  }

  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("error", () => { try { res.writeHead(400); res.end(); } catch {} });
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
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
    const reply = (obj) => {
      if (responded) return;
      responded = true;
      clearTimeout(timer);
      try {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(obj));
      } catch {}
    };

    try {
      const out = await core.handleRequest(body, { authenticated });
      reply(out);
    } catch (e) {
      console.log(`[sentinel] handler error: ${String(e).slice(0, 200)}`);
      reply({
        service: "sentinel",
        verdict: "REVIEW",
        reason_codes: ["RPC_ERROR"],
        error: "internal error while screening",
        checks: [],
        facts: null,
        proof: null,
        proof_omitted: "internal error — no complete fact set, so no proof applies",
        authenticated,
      });
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`sentinel listening on http://${HOST}:${PORT}/ (demo page) and POST http://${HOST}:${PORT}/api/guard (pid ${process.pid})`);
  console.log(`hmac: ${HMAC_SECRET ? "enabled (signed requests verified)" : "disabled (public demo mode)"}`);
});
