// Sentinel — wallet & transaction guard (shared core).
// zkVerify Agent Games Season 01, Wildcard track.
// Transport-agnostic: the caller supplies the parsed request body and the
// HMAC-authentication decision; the core returns the verdict object.
// The Vercel serverless entry (api/guard.js) and the local server
// (server.mjs) both use this core.
//
// Rule set (documented in README.md; the circuit proves the verdict
// follows from the observed facts by this rule):
//   BLOCK  if spender is the zero address
//          OR the token has no code
//          OR a bounded amount exceeds the wallet's token balance
//          OR the approval is unlimited AND the spender is unknown or has no code
//   REVIEW if the approval is unlimited (to a known spender)
//          OR the spender has no code (bounded amount)
//          OR the spender is unknown — not in the curated known-spender set
//          OR any fact is unknown (RPC error) — fail closed, never ALLOW
//          OR the input is invalid
//   ALLOW  otherwise (bounded amount, known spender, real token,
//          balance sufficient)
//
// "Known" vs "unknown" spender — why an allowlist (see README):
// public BSC full nodes prune historical state, so an on-chain age check
// ("deployed within the last N blocks") is impossible with free public
// infrastructure — eth_getCode fails with "missing trie node" even 128
// blocks back, the public archive endpoint times out, and BscScan's API
// returns a Cloudflare page from this environment. The fail-closed
// substitute is a curated KNOWN_SPENDERS set: any contract outside it is
// treated as unknown (which includes every newly-deployed contract).
// The set is intentionally small and documented; extend it only with an
// address + a public source in the list below.
//
// Thresholds (documented, deterministic):
//   UNLIMITED_THRESHOLD = 2^255 — any approval at or above it is treated as
//     unlimited (no legitimate bounded approval is that large).
//
// Secrets: none required. An optional SENTINEL_HMAC_SECRET enables
// HMAC-SHA256 verification of requests that carry an x-sentinel-signature
// header (same pattern as the Gatekeeper agent); unsigned requests are
// still served (public demo endpoint) and marked authenticated:false.
// Never commit a real secret.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as snarkjs from "snarkjs";

export const VERSION = "1.0.0";
export const CLAIM = "sentinel-v1";

// BSC mainnet public RPCs. bsc-dataseed needs a browser User-Agent (its
// default urllib UA gets HTTP 403); the fallback is tried on any failure.
export const RPC_URLS = [
  "https://bsc-dataseed.binance.org/",
  "https://bsc-dataseed1.defibit.io/",
];
const RPC_TIMEOUT_MS = 3000;
const USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";

// 2^255 — see README "Thresholds".
export const UNLIMITED_THRESHOLD = 1n << 255n;
export const MAX_UINT256 = (1n << 256n) - 1n;

// Curated known spenders (lowercase addresses). Only these contracts can
// ever receive an ALLOW. The set is intentionally small: every entry was
// verified on-chain, and a wrong entry here would silently bless approvals
// to the wrong contract. Extend it only with an address + a public source.
//   - PancakeSwap Router v2 (0x10ED...24E): the most-used DEX router on BSC;
//     verified live (has code; WETH()/factory() behave as the public router).
// A candidate PancakeSwap V3 router address (0x13f4EA83...) was REJECTED
// 2026-11-17 after an on-chain check showed it has NO code — do not add it
// without re-verifying.
export const KNOWN_SPENDERS = new Set([
  "0x10ed43c718714eb63d5aa57b78b54704e256024e", // PancakeSwap Router v2
]);

export const VERDICTS = { ALLOW: 0, REVIEW: 1, BLOCK: 2 };
export const VERDICT_NAMES = ["ALLOW", "REVIEW", "BLOCK"];

export const REASONS = {
  UNLIMITED_APPROVAL: "UNLIMITED_APPROVAL",
  SPENDER_ZERO_ADDRESS: "SPENDER_ZERO_ADDRESS",
  SPENDER_NO_CODE: "SPENDER_NO_CODE",
  SPENDER_UNKNOWN: "SPENDER_UNKNOWN",
  TOKEN_NO_CODE: "TOKEN_NO_CODE",
  AMOUNT_EXCEEDS_BALANCE: "AMOUNT_EXCEEDS_BALANCE",
  NOT_A_TOKEN: "NOT_A_TOKEN",
  RPC_ERROR: "RPC_ERROR",
  INVALID_INPUT: "INVALID_INPUT",
};

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// balanceOf(address) selector.
const BALANCE_OF_SELECTOR = "0x70a08231";

// ------------------------------------------------------------------ utils --
function isAddress(v) {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function parseAmount(raw) {
  if (typeof raw === "number" && Number.isInteger(raw) && raw >= 0) return BigInt(raw);
  if (typeof raw !== "string") return null;
  const s = raw.trim().toLowerCase();
  if (s === "max" || s === "unlimited" || s === "infinite") return MAX_UINT256;
  if (/^0x[0-9a-f]+$/.test(s)) {
    try { return BigInt(s); } catch { return null; }
  }
  if (/^\d+$/.test(s)) {
    try { return BigInt(s); } catch { return null; }
  }
  return null;
}

function toHex32(addr) {
  return "0x" + addr.slice(2).toLowerCase().padStart(64, "0");
}

function hexToBig(v) {
  if (typeof v !== "string") return null;
  try { return BigInt(v); } catch { return null; }
}

// ------------------------------------------------------------- artifact ---
export function resolveArtifactDir() {
  const here = path.dirname(fileURLToPath(import.meta.url)); // .../lib
  const candidates = [
    path.join(here, "..", "artifacts"),
    path.join(process.cwd(), "artifacts"),
  ];
  for (const dir of candidates) {
    if (existsSync(path.join(dir, "vk.json"))) return dir;
  }
  return candidates[0];
}

// -------------------------------------------------------------- RPC client -
// Tiny in-memory cache (per process): code lookups 60s, balances 30s,
// block number 5s. Cache keys never contain secrets.
function makeCache() {
  const store = new Map();
  return {
    get(key) {
      const e = store.get(key);
      if (!e || Date.now() > e.expiresAt) { store.delete(key); return undefined; }
      return e.value;
    },
    set(key, value, ttlMs) {
      store.set(key, { value, expiresAt: Date.now() + ttlMs });
    },
  };
}

async function fetchWithTimeout(url, options, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// One JSON-RPC call, trying each RPC URL in order. Throws on total failure.
async function rpcCall(method, params) {
  let lastErr = null;
  for (const url of RPC_URLS) {
    try {
      const res = await fetchWithTimeout(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          "user-agent": USER_AGENT,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      }, RPC_TIMEOUT_MS);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (json.error) throw new Error(`RPC error: ${json.error.message || JSON.stringify(json.error)}`);
      if (json.result === undefined) throw new Error("RPC: missing result");
      return json.result;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("RPC: all endpoints failed");
}

// ------------------------------------------------------------------ core --
export function createCore({ hmacSecret = "", artifactDir, rpcUrls } = {}) {
  if (rpcUrls && rpcUrls.length) RPC_URLS.splice(0, RPC_URLS.length, ...rpcUrls);
  const dir = artifactDir || resolveArtifactDir();
  const VK_PATH = path.join(dir, "vk.json");
  const WASM_PATH = path.join(dir, "sentinel.wasm");
  const ZKEY_PATH = path.join(dir, "sentinel_final.zkey");
  const INFO_PATH = path.join(dir, "circuit-info.json");

  let vk = null;
  let vkSha256 = null;
  let circuitInfo = null;
  try {
    vk = JSON.parse(readFileSync(VK_PATH, "utf8"));
    vkSha256 = createHash("sha256").update(readFileSync(VK_PATH)).digest("hex");
  } catch (e) {
    console.log(`[sentinel] WARNING: vk.json not loaded (${String(e).slice(0, 120)}) — proofs will be omitted`);
  }
  try {
    circuitInfo = JSON.parse(readFileSync(INFO_PATH, "utf8"));
  } catch { /* optional */ }

  const cache = makeCache();
  const artifactsReady = vk && existsSync(WASM_PATH) && existsSync(ZKEY_PATH);

  function hmacHex(rawBody) {
    if (!hmacSecret) return "";
    return createHmac("sha256", hmacSecret).update(rawBody).digest("hex");
  }

  function verifyHmac(rawBody, header) {
    if (!hmacSecret) return true; // no secret configured: public mode
    if (!header || typeof header !== "string") return true; // unsigned: public mode
    const expected = hmacHex(rawBody);
    const a = Buffer.from(expected, "utf8");
    const b = Buffer.from(header.trim().toLowerCase(), "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  }

  // --- RPC helpers (cached, throwing on failure) ---
  async function getBlockNumber() {
    const cached = cache.get("blockNumber");
    if (cached !== undefined) return cached;
    const hex = await rpcCall("eth_blockNumber", []);
    const n = hexToBig(hex);
    if (n === null) throw new Error("bad blockNumber");
    cache.set("blockNumber", n, 5000);
    return n;
  }

  async function getCode(address, blockTag) {
    const key = `code:${address.toLowerCase()}:${blockTag}`;
    const cached = cache.get(key);
    if (cached !== undefined) return cached;
    const code = await rpcCall("eth_getCode", [address, blockTag]);
    cache.set(key, code, 60000);
    return code;
  }

  async function getBalance(token, wallet) {
    const key = `balance:${token.toLowerCase()}:${wallet.toLowerCase()}`;
    const cached = cache.get(key);
    if (cached !== undefined) return cached;
    const data = BALANCE_OF_SELECTOR + toHex32(wallet).slice(2);
    const hex = await rpcCall("eth_call", [{ to: token, data }, "latest"]);
    const bal = hexToBig(hex);
    if (bal === null) throw new Error("bad balanceOf result");
    cache.set(key, bal, 30000);
    return bal;
  }

  // --- rule engine (pure, given facts) ---
  // facts: {unlimited, spenderZero, spenderNoCode, spenderUnknown, tokenNoCode,
  //         exceedsBalance} — each 0/1. Returns {verdictInt, reasonCodes}.
  function decide(facts) {
    const { unlimited, spenderZero, spenderNoCode, spenderUnknown, tokenNoCode, exceedsBalance } = facts;
    const block =
      spenderZero === 1 ||
      tokenNoCode === 1 ||
      exceedsBalance === 1 ||
      (unlimited === 1 && (spenderUnknown === 1 || spenderNoCode === 1));
    const reasons = [];
    if (unlimited === 1) reasons.push(REASONS.UNLIMITED_APPROVAL);
    if (spenderZero === 1) reasons.push(REASONS.SPENDER_ZERO_ADDRESS);
    if (spenderNoCode === 1) reasons.push(REASONS.SPENDER_NO_CODE);
    if (spenderUnknown === 1) reasons.push(REASONS.SPENDER_UNKNOWN);
    if (tokenNoCode === 1) reasons.push(REASONS.TOKEN_NO_CODE);
    if (exceedsBalance === 1) reasons.push(REASONS.AMOUNT_EXCEEDS_BALANCE);
    if (block) return { verdictInt: VERDICTS.BLOCK, reasonCodes: reasons };
    const review = unlimited === 1 || spenderNoCode === 1 || spenderUnknown === 1;
    if (review) return { verdictInt: VERDICTS.REVIEW, reasonCodes: reasons };
    return { verdictInt: VERDICTS.ALLOW, reasonCodes: reasons };
  }

  // --- proof ---
  async function prove(facts, verdictInt) {
    if (!artifactsReady) {
      return { proof: null, publicSignals: null, omitted: "proof artifacts (wasm/zkey/vk) not available in this deployment" };
    }
    const input = { ...facts, verdict: verdictInt };
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
      const ok = await snarkjs.groth16.verify(vk, publicSignals, proof).catch(() => false);
      if (!ok) {
        console.log("[sentinel] WARNING: locally generated proof failed self-verification");
        return { proof: null, publicSignals: null, omitted: "generated proof failed local self-verification" };
      }
      return { proof, publicSignals, omitted: null };
    } catch (e) {
      console.log(`[sentinel] proof generation failed: ${String(e).slice(0, 200)}`);
      return { proof: null, publicSignals: null, omitted: `proof generation failed: ${String(e).slice(0, 120)}` };
    }
  }

  // --- main handler ---
  // body: parsed JSON request. opts.authenticated: whether the request
  // carried a valid HMAC signature (public mode otherwise).
  // Never throws for a well-formed body; returns the verdict object.
  async function handleRequest(body, opts = {}) {
    const t0 = Date.now();
    const authenticated = opts.authenticated === true;
    const base = {
      service: "sentinel",
      version: VERSION,
      claim: CLAIM,
      authenticated,
      checkedAt: new Date().toISOString(),
    };

    // ---- input validation ----
    const errors = [];
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      errors.push("body must be a JSON object");
    } else {
      if (body.type !== undefined && body.type !== "sentinel.guard.v1") {
        errors.push(`unknown type: ${String(body.type).slice(0, 80)}`);
      }
      if (body.kind !== undefined && body.kind !== "approval") {
        errors.push(`unsupported kind: ${String(body.kind).slice(0, 80)} (v1 screens approvals only)`);
      }
      if (!isAddress(body.wallet)) errors.push("wallet must be a 0x address (40 hex chars)");
      if (!isAddress(body.token)) errors.push("token must be a 0x address (40 hex chars)");
      if (!isAddress(body.spender)) errors.push("spender must be a 0x address (40 hex chars)");
      if (parseAmount(body.amount) === null) errors.push("amount must be a non-negative integer, a 0x hex integer, or \"max\"");
    }
    if (errors.length) {
      return {
        ...base,
        verdict: "REVIEW",
        reason_codes: [REASONS.INVALID_INPUT],
        error: errors.join("; "),
        checks: [{ name: "input_validation", outcome: "fail", detail: errors.join("; ") }],
        facts: null,
        proof: null,
        proof_omitted: "input invalid — no on-chain facts were gathered, so no proof applies",
        tookMs: Date.now() - t0,
      };
    }

    const wallet = body.wallet.toLowerCase();
    const token = body.token.toLowerCase();
    const spender = body.spender.toLowerCase();
    const amount = parseAmount(body.amount);
    const unlimited = amount >= UNLIMITED_THRESHOLD ? 1 : 0;
    const spenderZero = spender === ZERO_ADDRESS ? 1 : 0;

    // ---- gather facts (each independent; failures mark that check unknown) ----
    const checks = [];
    const check = (name, outcome, detail) => {
      checks.push({ name, outcome, detail });
      return outcome;
    };

    let blockNumber = null;
    try {
      blockNumber = await getBlockNumber();
    } catch (e) {
      check("chain_block_number", "unknown", `eth_blockNumber failed: ${String(e).slice(0, 100)}`);
    }

    let tokenCode = null;
    let tokenCodeKnown = false;
    try {
      tokenCode = await getCode(token, "latest");
      tokenCodeKnown = true;
    } catch (e) {
      check("token_has_code", "unknown", `eth_getCode(token) failed: ${String(e).slice(0, 100)}`);
    }

    let spenderCode = null;
    let spenderCodeKnown = false;
    try {
      spenderCode = await getCode(spender, "latest");
      spenderCodeKnown = true;
    } catch (e) {
      check("spender_has_code", "unknown", `eth_getCode(spender) failed: ${String(e).slice(0, 100)}`);
    }

    const tokenHasCode = tokenCodeKnown ? tokenCode !== "0x" && tokenCode.length > 2 : null;
    const spenderHasCode = spenderCodeKnown ? spenderCode !== "0x" && spenderCode.length > 2 : null;
    if (tokenCodeKnown) check("token_has_code", tokenHasCode ? "pass" : "fail", tokenHasCode ? "token is a contract" : "token address has no code — not a contract");
    if (spenderCodeKnown) check("spender_has_code", spenderHasCode ? "pass" : "fail", spenderHasCode ? "spender is a contract" : "spender has no code (EOA or non-contract)");

    // Spender reputation: "known" means in the curated KNOWN_SPENDERS set.
    // A contract outside the set is treated as unknown — which includes
    // every newly-deployed contract (see the header comment for why an
    // on-chain age check is not implementable here). This is a local
    // check, so it is always known.
    const spenderKnown = spenderHasCode === true ? KNOWN_SPENDERS.has(spender) : null;
    const spenderUnknown = spenderHasCode === true && !spenderKnown ? 1 : 0;
    if (spenderHasCode === true) {
      check("spender_known", spenderKnown ? "pass" : "fail",
        spenderKnown
          ? "spender is in the curated known-spender set"
          : "spender is a contract but NOT in the known-spender set — treated as unknown (covers newly-deployed contracts)");
    } else if (spenderHasCode === false) {
      check("spender_known", "fail", "skipped — spender has no code, the known-set check does not apply");
    }

    // Balance (only meaningful if the token is a contract).
    let balance = null;
    let balanceKnown = false;
    let notAToken = false;
    if (tokenHasCode === true) {
      try {
        balance = await getBalance(token, wallet);
        balanceKnown = true;
      } catch (e) {
        // A revert here means the contract does not implement balanceOf —
        // it is not a standard ERC-20, not (only) an RPC outage.
        const msg = String(e);
        if (/revert|execution reverted|missing revert|invalid/i.test(msg)) {
          notAToken = true;
          check("token_is_erc20", "fail", "balanceOf call reverted — contract does not behave like an ERC-20 token");
        } else {
          check("token_balance", "unknown", `balanceOf failed: ${msg.slice(0, 100)}`);
        }
      }
    } else if (tokenHasCode === false) {
      check("token_is_erc20", "fail", "skipped — token has no code");
    }

    const exceedsBalance = balanceKnown && unlimited === 0 ? (amount > balance ? 1 : 0) : 0;
    if (balanceKnown) {
      check("amount_within_balance", exceedsBalance === 0 ? "pass" : "fail",
        unlimited === 1
          ? "unlimited amount — balance comparison skipped (the unlimited flag carries the risk)"
          : `amount ${amount.toString()} vs balance ${balance.toString()}`);
    }
    check("unlimited_approval", unlimited === 1 ? "fail" : "pass",
      unlimited === 1 ? `amount ${amount.toString()} is at/above the unlimited threshold 2^255` : "amount is bounded");
    if (spenderZero === 1) check("spender_zero_address", "fail", "spender is the zero address");
    if (notAToken) {
      // Not a standard token: fail closed to REVIEW, no proof.
      return {
        ...base,
        verdict: "REVIEW",
        reason_codes: [REASONS.NOT_A_TOKEN],
        checks,
        facts: {
          blockNumber: blockNumber?.toString() ?? null,
          tokenHasCode,
          spenderHasCode,
          spenderKnown,
          balance: null,
          amount: amount.toString(),
          unlimited: unlimited === 1,
        },
        proof: null,
        proof_omitted: "token does not implement ERC-20 balanceOf — no complete fact set, so no proof applies",
        tookMs: Date.now() - t0,
      };
    }

    // blockNumber is informational only (when the check ran); a failed
    // blockNumber call does not gate the verdict.
    const unknownFacts =
      !tokenCodeKnown ||
      !spenderCodeKnown ||
      (tokenHasCode === true && !balanceKnown);

    const facts = {
      blockNumber: blockNumber?.toString() ?? null,
      tokenHasCode,
      spenderHasCode,
      spenderKnown,
      balance: balanceKnown ? balance.toString() : null,
      amount: amount.toString(),
      unlimited: unlimited === 1,
    };

    if (unknownFacts) {
      // Fail closed: REVIEW unless a KNOWN fact already forces BLOCK.
      const knownBlock =
        spenderZero === 1 ||
        tokenHasCode === false ||
        (balanceKnown && unlimited === 0 && amount > balance);
      const reasonCodes = [REASONS.RPC_ERROR];
      if (spenderZero === 1) reasonCodes.push(REASONS.SPENDER_ZERO_ADDRESS);
      if (tokenHasCode === false) reasonCodes.push(REASONS.TOKEN_NO_CODE);
      if (unlimited === 1) reasonCodes.push(REASONS.UNLIMITED_APPROVAL);
      return {
        ...base,
        verdict: knownBlock ? "BLOCK" : "REVIEW",
        reason_codes: reasonCodes,
        checks,
        facts,
        proof: null,
        proof_omitted: "one or more on-chain facts could not be observed (RPC error) — the verdict is fail-closed and no proof applies",
        tookMs: Date.now() - t0,
      };
    }

    // All facts known: apply the rule and prove it.
    const bits = {
      unlimited,
      spenderZero,
      spenderNoCode: spenderHasCode ? 0 : 1,
      spenderUnknown,
      tokenNoCode: tokenHasCode ? 0 : 1,
      exceedsBalance,
    };
    const { verdictInt, reasonCodes } = decide(bits);
    const { proof, publicSignals, omitted } = await prove(bits, verdictInt);

    return {
      ...base,
      verdict: VERDICT_NAMES[verdictInt],
      reason_codes: reasonCodes,
      checks,
      facts,
      proof: proof
        ? {
            claim: CLAIM,
            protocol: "groth16",
            curve: "bn128",
            proof,
            public_signals: publicSignals,
            vk_sha256: vkSha256,
            verify_with: "snarkjs groth16 verify artifacts/vk.json <public_signals> <proof> (see README)",
          }
        : null,
      proof_omitted: omitted,
      tookMs: Date.now() - t0,
    };
  }

  function handleGet() {
    return {
      ok: true,
      service: "sentinel",
      version: VERSION,
      claim: CLAIM,
      time: new Date().toISOString(),
      rules: "POST /api/guard with {wallet, token, spender, amount} — see README.md",
      thresholds: {
        unlimited: "amount >= 2^255",
        known_spenders: [...KNOWN_SPENDERS],
        known_spenders_note: "only these contracts can receive an ALLOW; any other contract spender is treated as unknown",
      },
      proof: {
        protocol: "groth16",
        curve: "bn128",
        vk_sha256: vkSha256,
        artifacts_ready: artifactsReady,
        public_signals: circuitInfo?.publicSignals ?? ["unlimited", "spenderZero", "spenderNoCode", "spenderUnknown", "tokenNoCode", "exceedsBalance", "verdict"],
      },
    };
  }

  return { hmacHex, verifyHmac, decide, handleRequest, handleGet, REASONS, VERDICTS };
}
