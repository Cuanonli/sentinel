// Sentinel — local end-to-end tests.
// Spawns the local server (server.mjs) on a test port with a dummy HMAC
// secret, then exercises it over real HTTP against the live BSC RPC.
// No Vercel token, no deployment, no money moved (read-only RPC calls).
//
// Run:  node test-guard.mjs
// Requires: circuit artifacts present (bash scripts/setup-circuit.sh first).
//
// Cases (the four required by the task, plus extras):
//   1. unlimited USDT approval to an unknown spender -> BLOCK
//   2. small bounded approval to a well-known spender -> ALLOW
//   3. approval exceeding the wallet's balance -> BLOCK
//   4. malformed input -> REVIEW with a clear error, no crash
//   +  GET /api/guard health, zero-address spender -> BLOCK,
//      token with no code -> BLOCK, HMAC signed/unsigned/bad-signature,
//      and Groth16 proof verification for every proof returned.

import { spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import * as snarkjs from "snarkjs";

const PORT = 3456;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "test-dummy-secret-123";
const USDT = "0x55d398326f99059fF775485246999027B3197955";
const ROUTER = "0x10ED43C718714eb63d5aA57B78B54704E256024E"; // PancakeSwap Router v2
const BINANCE_HOT = "0xF977814e90dA44bFA03b6295A0616a897441aceC"; // known USDT holder
const EMPTY_WALLET = "0x9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00"; // 0 USDT balance (verified on-chain)
const UNKNOWN_SPENDER = "0x1234567890123456789012345678901234567890"; // no code
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

let pass = 0;
let fail = 0;
function check(label, ok, extra = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${label}${extra ? " — " + extra : ""}`);
  ok ? pass++ : fail++;
}

const VK_PATH = new URL("./artifacts/vk.json", import.meta.url);
if (!existsSync(VK_PATH)) {
  console.error("FATAL: artifacts/vk.json missing — run: bash scripts/setup-circuit.sh");
  process.exit(2);
}
const VK = JSON.parse(readFileSync(VK_PATH, "utf8"));

function sign(body) {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

async function post(path, obj, { signed = false, badSig = false } = {}) {
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (signed) headers["x-sentinel-signature"] = sign(body);
  if (badSig) headers["x-sentinel-signature"] = "deadbeef";
  const res = await fetch(`${BASE}${path}`, { method: "POST", headers, body });
  return { status: res.status, json: await res.json().catch(() => null) };
}

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  return { status: res.status, json: await res.json().catch(() => null) };
}

async function verifyProof(label, out) {
  if (!out?.proof) {
    check(`${label} proof present`, false, out?.proof_omitted || "no proof and no reason given");
    return;
  }
  const ok = await snarkjs.groth16.verify(VK, out.proof.public_signals, out.proof.proof);
  check(`${label} Groth16 proof verifies against vk.json`, ok === true, `signals=[${out.proof.public_signals?.join(",")}]`);
  // Public signals must encode the verdict (last signal) and the rule bits.
  const sig = out.proof.public_signals || [];
  check(`${label} proof public signals encode the verdict`, sig.length === 7 && Number(sig[6]) === ({ ALLOW: 0, REVIEW: 1, BLOCK: 2 })[out.verdict], `verdict=${out.verdict} signals=${JSON.stringify(sig)}`);
}

function waitForServer(proc, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = async () => {
      try {
        const r = await fetch(`${BASE}/api/guard`);
        if (r.ok) return resolve();
      } catch { /* not up yet */ }
      if (Date.now() - t0 > timeoutMs) return reject(new Error("server did not start in time"));
      setTimeout(tick, 300);
    };
    tick();
  });
}

const server = spawn(process.execPath, ["server.mjs"], {
  cwd: new URL(".", import.meta.url).pathname,
  env: { ...process.env, PORT: String(PORT), HOST: "127.0.0.1", SENTINEL_HMAC_SECRET: SECRET },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => process.stdout.write(`[server] ${d}`));
server.stderr.on("data", (d) => process.stdout.write(`[server:err] ${d}`));

try {
  await waitForServer(server);

  // 0. Health ---------------------------------------------------------------
  {
    const { status, json } = await get("/api/guard");
    check("GET /api/guard status 200", status === 200, `status=${status}`);
    check("GET /api/guard service sentinel", json?.ok === true && json?.service === "sentinel", JSON.stringify(json)?.slice(0, 120));
    check("GET /api/guard artifacts ready", json?.proof?.artifacts_ready === true, `artifacts_ready=${json?.proof?.artifacts_ready}`);
  }

  // 1. Unlimited USDT approval to an unknown spender -> BLOCK ---------------
  {
    const { status, json } = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: USDT, spender: UNKNOWN_SPENDER, amount: "max",
    });
    check("case 1 status 200", status === 200, `status=${status}`);
    check("case 1 BLOCK", json?.verdict === "BLOCK", `verdict=${json?.verdict}`);
    check("case 1 reason UNLIMITED_APPROVAL", (json?.reason_codes || []).includes("UNLIMITED_APPROVAL"), `reasons=${JSON.stringify(json?.reason_codes)}`);
    check("case 1 reason SPENDER_NO_CODE", (json?.reason_codes || []).includes("SPENDER_NO_CODE"), `reasons=${JSON.stringify(json?.reason_codes)}`);
    await verifyProof("case 1", json);
    console.log(`  (case 1 took ${json?.tookMs}ms)`);
  }

  // 2. Small bounded approval to a well-known spender -> ALLOW --------------
  {
    const { status, json } = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: USDT, spender: ROUTER, amount: "1000000000000000000",
    });
    check("case 2 status 200", status === 200, `status=${status}`);
    check("case 2 ALLOW", json?.verdict === "ALLOW", `verdict=${json?.verdict} reasons=${JSON.stringify(json?.reason_codes)}`);
    await verifyProof("case 2", json);
    console.log(`  (case 2 took ${json?.tookMs}ms)`);
  }

  // 3. Approval exceeding the wallet's balance -> BLOCK ----------------------
  {
    const { status, json } = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: EMPTY_WALLET, token: USDT, spender: ROUTER, amount: "1000000000000000000000",
    });
    check("case 3 status 200", status === 200, `status=${status}`);
    check("case 3 BLOCK", json?.verdict === "BLOCK", `verdict=${json?.verdict}`);
    check("case 3 reason AMOUNT_EXCEEDS_BALANCE", (json?.reason_codes || []).includes("AMOUNT_EXCEEDS_BALANCE"), `reasons=${JSON.stringify(json?.reason_codes)}`);
    await verifyProof("case 3", json);
    console.log(`  (case 3 took ${json?.tookMs}ms)`);
  }

  // 4. Malformed input -> REVIEW with a clear error, no crash ---------------
  {
    const { status, json } = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: "not-an-address", token: USDT, spender: ROUTER, amount: "abc",
    });
    check("case 4 status 200", status === 200, `status=${status}`);
    check("case 4 REVIEW", json?.verdict === "REVIEW", `verdict=${json?.verdict}`);
    check("case 4 reason INVALID_INPUT", (json?.reason_codes || []).includes("INVALID_INPUT"), `reasons=${JSON.stringify(json?.reason_codes)}`);
    check("case 4 has a clear error message", typeof json?.error === "string" && json.error.length > 0, json?.error);
    check("case 4 proof omitted with a statement", json?.proof === null && typeof json?.proof_omitted === "string", json?.proof_omitted);
  }

  // 5. Zero-address spender -> BLOCK ----------------------------------------
  {
    const { json } = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: USDT, spender: ZERO_ADDRESS, amount: "1000000000000000000",
    });
    check("zero spender BLOCK", json?.verdict === "BLOCK", `verdict=${json?.verdict}`);
    check("zero spender reason SPENDER_ZERO_ADDRESS", (json?.reason_codes || []).includes("SPENDER_ZERO_ADDRESS"));
    await verifyProof("zero spender", json);
  }

  // 6. Token with no code -> BLOCK -------------------------------------------
  {
    const { json } = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: UNKNOWN_SPENDER, spender: ROUTER, amount: "1000000000000000000",
    });
    check("no-code token BLOCK", json?.verdict === "BLOCK", `verdict=${json?.verdict}`);
    check("no-code token reason TOKEN_NO_CODE", (json?.reason_codes || []).includes("TOKEN_NO_CODE"));
    await verifyProof("no-code token", json);
  }

  // 7. HMAC: signed request accepted, bad signature 401, unsigned is public -
  {
    const signed = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: USDT, spender: ROUTER, amount: "1000000000000000000",
    }, { signed: true });
    check("signed request 200 + authenticated:true", signed.status === 200 && signed.json?.authenticated === true, `status=${signed.status} authenticated=${signed.json?.authenticated}`);
    const bad = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: USDT, spender: ROUTER, amount: "1000000000000000000",
    }, { badSig: true });
    check("bad signature -> 401", bad.status === 401, `status=${bad.status}`);
    const unsigned = await post("/api/guard", {
      type: "sentinel.guard.v1", wallet: BINANCE_HOT, token: USDT, spender: ROUTER, amount: "1000000000000000000",
    });
    check("unsigned request served as public (200, authenticated:false)", unsigned.status === 200 && unsigned.json?.authenticated === false, `status=${unsigned.status} authenticated=${unsigned.json?.authenticated}`);
  }

  // 8. Invalid JSON body -> 400, server still alive --------------------------
  {
    const { status } = await post("/api/guard", "{not json");
    check("invalid JSON -> 400", status === 400, `status=${status}`);
    const { status: s2, json } = await get("/api/guard");
    check("server still alive after invalid JSON", s2 === 200 && json?.ok === true);
  }
} finally {
  server.kill("SIGTERM");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
