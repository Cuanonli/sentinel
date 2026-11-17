# Sentinel — wallet & transaction guard

**zkVerify Agent Games Season 01 · Wildcard track**

Sentinel screens an ERC-20 approval *before* you sign it and tells you, in plain
terms, whether it is safe: **ALLOW / REVIEW / BLOCK** — with the exact checks that
ran, the on-chain facts behind them, and a Groth16 proof that the verdict
followed the published rule set.

- Live demo: `https://<deployment>/` (paste an approval, see the verdict)
- API: `POST https://<deployment>/api/guard`
- Chain: BSC mainnet (read-only public RPC, no keys, no signing, no funds move)

## Use case — the problem, who it helps

Unlimited token approvals are the single most common way wallets get drained:
a user approves a random dApp "to save gas", the approval is infinite, and
weeks later the spender — or whoever controls it — empties the wallet. The
same pattern repeats with approvals to contracts that were deployed minutes
ago, approvals to addresses that are not contracts at all, and approvals
larger than the wallet's balance.

Existing blockers (revoke.cash, wallet warnings) are reactive: they show you
the damage after the approval exists. Sentinel is **pre-signing**: paste the
approval (or have your wallet/agent call the endpoint first) and get a
verdict *before* anything is signed.

Who it helps:
- **Everyday wallet users** — a second opinion before signing an approval,
  in words a non-developer can act on.
- **AI agents that move funds** — an agent can call Sentinel before signing
  on a user's behalf, and the verdict is machine-readable (plus a proof).
- **dApp and wallet developers** — a drop-in screening endpoint with a
  deterministic, published rule set.

## How it works

```
POST /api/guard
{ "type": "sentinel.guard.v1",
  "wallet": "0x...", "token": "0x...", "spender": "0x...",
  "amount": "1000000000000000000" | "0x..." | "max" }
        │
        ▼
  1. Validate the input (bad address / bad amount → REVIEW, INVALID_INPUT)
  2. Read on-chain facts from the BSC public RPC (no API key):
       • token code, spender code            (eth_getCode, latest)
       • wallet's token balance              (eth_call balanceOf)
       • current block number                (eth_blockNumber)
  3. Apply the published rule set → verdict
  4. Generate a Groth16 proof that the verdict follows from the facts
  5. Return verdict + reason codes + checks + facts + proof
```

The response is always HTTP 200 for a well-formed request (even for BLOCK —
a BLOCK is a successful screening, not an error). Malformed JSON returns 400;
a present-but-invalid HMAC signature returns 401 (see below).

### The rule set

Facts are encoded as bits: `unlimited`, `spenderZero`, `spenderNoCode`,
`spenderUnknown`, `tokenNoCode`, `exceedsBalance`.

| Verdict | Condition |
|---|---|
| **BLOCK** | spender is the zero address · token has no code · a bounded amount exceeds the wallet's token balance · approval is unlimited **and** the spender is unknown or has no code |
| **REVIEW** | approval is unlimited (to a known spender) · spender has no code · spender is unknown (not in the curated known-spender set) · any fact could not be observed (RPC error) · input invalid |
| **ALLOW** | none of the above — bounded amount, real token contract, balance sufficient, spender is a known contract |

### Thresholds (documented, deterministic)

- **Unlimited** — amount ≥ 2^255 (or exactly 2^256−1, or the string `"max"`).
  No legitimate bounded approval is that large.
- **Known spender** — the spender is in the curated `KNOWN_SPENDERS` set in
  `lib/sentinel.mjs`. Only those contracts can ever receive an ALLOW.

### Why an allowlist — the one honest compromise

The first version of this guard checked "newly deployed" on-chain: code now,
no code 1,000,000 blocks ago. Testing killed that design. Public BSC full
nodes prune historical state, so `eth_getCode` at any old block fails with
`missing trie node` — even 128 blocks back (verified 2026-11-17 against
bsc-dataseed, defibit, bnbchain and ninicoin endpoints). The public archive
endpoint times out, and BscScan's API returns a Cloudflare page from this
environment. So an on-chain age check is **not implementable with free
public infrastructure**.

The fail-closed substitute is the curated known-spender set: any contract
outside it is treated as unknown — which includes every newly-deployed
contract by definition. Unknown spenders get REVIEW (or BLOCK when the
approval is unlimited), never ALLOW. The set is intentionally small (today:
PancakeSwap Router v2 only — every entry verified on-chain) and can only be
extended with an address + a public source. A candidate PancakeSwap V3 router
address was rejected on 2026-11-17 after an on-chain check showed it has no
code; it must not be added without re-verifying.

### What it can and cannot do

Can:
- Screen ERC-20 `approve` requests on BSC mainnet (v1 is approvals only).
- Detect unlimited approvals, zero-address spenders, non-contract tokens and
  spenders, unknown spenders, and amounts above the wallet's balance.
- Prove the verdict followed the rule set (Groth16, claim `sentinel-v1`).
- Run read-only: it never signs, never sends a transaction, never moves funds.

Cannot:
- Verify that the RPC facts themselves are true — the proof covers the rule
  application, not the data source. The facts are public and independently
  checkable on-chain (the response includes them).
- Detect a malicious contract that is *already* well-known, or a token whose
  code is a perfect clone of a legitimate one. The guard checks the
  *approval*, not the contract's intent.
- Screen transfers, swaps, or other transaction types in v1 (only approvals).
- Work on chains other than BSC mainnet in v1 (the RPC client is BSC-only).

### Optional HMAC

Sentinel is a public demo endpoint, so requests are accepted unsigned. If
`SENTINEL_HMAC_SECRET` is set, a request carrying an
`x-sentinel-signature` header (HMAC-SHA256 hex over the raw body) must verify
— a bad signature returns 401. Unsigned requests are still served and marked
`authenticated: false` in the response. This reuses the pattern from the
Proof Gatekeeper agent in the same competition. Never commit a real secret.

### Fail-closed behaviour

- Any RPC fact that cannot be observed → verdict REVIEW (or BLOCK if a
  *known* fact already forces it), reason `RPC_ERROR`, no proof, and a clear
  `proof_omitted` statement.
- Input that fails validation → REVIEW, reason `INVALID_INPUT`, no proof.
- A request that takes longer than 8s → REVIEW, `RPC_ERROR` (Vercel Hobby
  maxDuration is 10s; the guard never hangs).
- The server never crashes on a bad request (see `test-guard.mjs`, case 4
  and the invalid-JSON case).

## Run locally

```bash
npm install
bash scripts/setup-circuit.sh   # compile circuit + local trusted setup (needs circom 2.2.x)
npm test                        # end-to-end tests against the live BSC RPC
npm start                       # http://127.0.0.1:3000/ (demo) + POST /api/guard
```

`scripts/setup-circuit.sh` needs the `circom` binary (download:
`https://github.com/iden3/circom/releases/download/v2.2.2/circom-linux-amd64`).
It runs a small local Powers of Tau ceremony (bn128, 2^12) with a single
contribution, then a Groth16 setup, and writes `artifacts/` (wasm, zkey,
vk.json, circuit-info.json). The ceremony transcript stays in `build/`.

## Demo

Open the demo page and paste an approval, or try the presets:

1. **Unlimited USDT approval to an unknown spender → BLOCK**
   (`UNLIMITED_APPROVAL`, `SPENDER_NO_CODE`)
2. **Small bounded approval to PancakeSwap Router v2 → ALLOW**
3. **Approval larger than the wallet's balance → BLOCK**
   (`AMOUNT_EXCEEDS_BALANCE`)
4. **Malformed input → REVIEW** with a clear error, no crash

Or with curl:

```bash
curl -X POST http://127.0.0.1:3000/api/guard \
  -H 'content-type: application/json' \
  -d '{"wallet":"0xF977814e90dA44bFA03b6295A0616a897441aceC",
       "token":"0x55d398326f99059fF775485246999027B3197955",
       "spender":"0x10ED43C718714eb63d5aA57B78B54704E256024E",
       "amount":"1000000000000000000"}'
```

## Deploy (Vercel)

```bash
vercel deploy   # or import the repo in the Vercel dashboard
```

The project is the same shape as the Proof Gatekeeper agent: `api/guard.js`
is the serverless entry, `vercel.json` bundles the proving artifacts
(`artifacts/{sentinel.wasm,sentinel_final.zkey,vk.json,circuit-info.json}`)
and sets `maxDuration: 10`. Set `SENTINEL_HMAC_SECRET` in the Vercel env
vars only if you want signed requests. No other env vars are needed.

## The zkVerify note — the checkable claim

**Claim (`sentinel-v1`):** given the observed on-chain facts (encoded as
public signals), the verdict is exactly the output of the published rule
function. The circuit is `circuits/sentinel.circom` (Groth16, BN128, 14
non-linear constraints, 7 public signals):

```
public signals: [unlimited, spenderZero, spenderNoCode, spenderUnknown,
                 tokenNoCode, exceedsBalance, verdict]
verdict: 0 = ALLOW, 1 = REVIEW, 2 = BLOCK
```

Every response with a complete fact set includes the Groth16 proof and its
public signals. The verification key is published in `artifacts/vk.json`
(SHA-256 `e54fe9c7793e78c1439bff11a62952167743fe0a9442573baa834f71c0d67bed`;
see `artifacts/circuit-info.json` for the artifact hashes).

**Verifying a proof** (offline, with the repo checked out):

```bash
# 1. Save the proof + public signals from a response into proof.json / signals.json
#    (the demo page shows them; the API returns them under "proof")
# 2. Verify against the published verification key:
npx snarkjs groth16 verify artifacts/vk.json signals.json proof.json
```

**What the proof does and does not cover.** It proves the verdict followed
the rule from the facts — it does *not* prove the RPC facts themselves. The
facts are public: anyone can re-run `eth_getCode` / `eth_call balanceOf`
against BSC and check them. When any fact is unknown, no proof is produced
and the response says so (`proof_omitted`) — a missing proof is itself a
signal, not a silent gap.

**Setup honesty.** The proving keys come from a local single-contributor
Powers of Tau ceremony (bn128, 2^12) run by `scripts/setup-circuit.sh`.
That is fine for a demo / competition entry — the claim is "the verdict
followed the published rule", verified against the published `vk.json` — but
it is **not** a production trusted setup, and it is documented as such in
`artifacts/circuit-info.json`. The ceremony transcript (`build/`) is kept so
anyone can re-run it.

## API reference

`GET /api/guard` → service info, rule summary, thresholds, `vk_sha256`,
`artifacts_ready`.

`POST /api/guard` — body:

```json
{ "type": "sentinel.guard.v1",
  "wallet": "0x...", "token": "0x...", "spender": "0x...",
  "amount": "1000000000000000000" }
```

`amount` accepts a decimal string, a `0x` hex integer, a JSON number, or
`"max"` / `"unlimited"`. Response:

```json
{ "service": "sentinel", "version": "1.0.0", "claim": "sentinel-v1",
  "verdict": "ALLOW",
  "reason_codes": [],
  "checks": [ { "name": "spender_known", "outcome": "pass",
                "detail": "spender is in the curated known-spender set" } ],
  "facts": { "blockNumber": "134127598", "tokenHasCode": true,
             "spenderHasCode": true, "spenderKnown": true,
             "balance": "5000000000000000000000", "amount": "1000000000000000000",
             "unlimited": false },
  "proof": { "claim": "sentinel-v1", "protocol": "groth16",
             "curve": "bn128", "proof": { "pi_a": [...] },
             "public_signals": ["0","0","0","0","0","0","0"],
             "vk_sha256": "e54fe9c7…" },
  "proof_omitted": null,
  "tookMs": 812, "authenticated": false }
```

## Tests

`node test-guard.mjs` — spins up the local server and tests it over real
HTTP against the live BSC RPC. See [TESTS.md](TESTS.md) for the cases and
the results.

## Files

| Path | What it is |
|---|---|
| `lib/sentinel.mjs` | Shared core: RPC client, rule engine, proof generation, HMAC |
| `api/guard.js` | Vercel serverless entry (`POST /api/guard`) |
| `server.mjs` | Local server + static demo page |
| `public/index.html` | Public demo page |
| `circuits/sentinel.circom` | The `sentinel-v1` circuit |
| `scripts/setup-circuit.sh` | Compile + trusted setup + sample-proof check |
| `artifacts/` | `sentinel.wasm`, `sentinel_final.zkey`, `vk.json`, `circuit-info.json` |
| `test-guard.mjs` | End-to-end tests (live BSC RPC) |
| `TESTS.md` | Test record: cases, results, bugs found |
| `SUBMISSION.md` | The exact texts to paste into the Wildcard submission form |
