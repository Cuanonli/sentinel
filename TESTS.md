# Sentinel — test record

## How to run

```bash
npm install
bash scripts/setup-circuit.sh   # required first (builds artifacts/)
node test-guard.mjs             # spins up the local server on port 3456
```

The suite tests the real local server over HTTP against the **live BSC
mainnet RPC** — no mocks, no testnet, no fake chain state. Nothing is
signed and no transaction is sent (all RPC calls are read-only:
`eth_blockNumber`, `eth_getCode`, `eth_call balanceOf`).

## Latest run

- **When:** 17 Nov 2026 ~20:42 WIB (13:42 UTC)
- **Result: 36 passed, 0 failed** (`node test-guard.mjs`, exit 0)
- **Command:** `node test-guard.mjs` from the project root

## Cases

| # | Case | Expected | Observed |
|---|---|---|---|
| 0 | `GET /api/guard` | 200, service sentinel, artifacts ready | 200, `artifacts_ready: true` |
| 1 | Unlimited USDT approval to an unknown spender (wallet: Binance hot wallet, spender: `0x1234…7890`, amount: `max`) | BLOCK, `UNLIMITED_APPROVAL` + `SPENDER_NO_CODE`, proof verifies | BLOCK, same reasons, proof verifies (signals `[1,0,1,0,0,0,2]`), 1,574 ms |
| 2 | Small bounded approval to a well-known spender (1 USDT to PancakeSwap Router v2) | ALLOW, proof verifies | ALLOW, no reasons, proof verifies (signals `[0,0,0,0,0,0,0]`), 264 ms |
| 3 | Approval exceeding the wallet's balance (1,000 USDT from a 0-balance wallet) | BLOCK, `AMOUNT_EXCEEDS_BALANCE`, proof verifies | BLOCK, same reason, proof verifies (signals `[0,0,0,0,0,1,2]`), 190 ms |
| 4 | Malformed input (bad wallet, amount `"abc"`) | REVIEW, `INVALID_INPUT`, clear error, no crash | REVIEW, same reason, error message names both bad fields, proof omitted with a statement |
| 5 | Zero-address spender | BLOCK, `SPENDER_ZERO_ADDRESS`, proof verifies | BLOCK, same reason, proof verifies (signals `[0,1,1,0,0,0,2]`) |
| 6 | Token with no code (spender address used as the token) | BLOCK, `TOKEN_NO_CODE`, proof verifies | BLOCK, same reason, proof verifies (signals `[0,0,0,0,1,0,2]`) |
| 7 | HMAC (server started with a dummy secret) | signed → 200 + `authenticated: true`; bad signature → 401; unsigned → 200 + `authenticated: false` | all three as expected |
| 8 | Invalid JSON body | 400, server stays alive | 400, then `GET /api/guard` still 200 |

Every response that carries a proof is verified in-test with
`snarkjs.groth16.verify(vk, publicSignals, proof)` against
`artifacts/vk.json`, and the test also checks that the last public signal
equals the verdict (0=ALLOW, 1=REVIEW, 2=BLOCK).

## Bugs found by testing (and fixed)

These are recorded because they changed the design — they are not hidden:

1. **Historical `eth_getCode` does not work on public BSC nodes.**
   The first design checked "newly deployed" as code-now / no-code-1,000,000-
   blocks-ago. Cases 2, 3 and 6 failed with `RPC_ERROR`: every public BSC
   full node (bsc-dataseed, defibit, bnbchain, ninicoin) fails historical
   `eth_getCode` with `missing trie node` — even 128 blocks back. The public
   archive endpoint times out and BscScan's API returns a Cloudflare page.
   Fix: the age check was replaced by a curated known-spender set
   (`KNOWN_SPENDERS` in `lib/sentinel.mjs`); any contract outside it is
   treated as unknown, which includes every newly-deployed contract. The
   circuit input was renamed `spenderNew` → `spenderUnknown` and the keys
   were regenerated. See README "Why an allowlist".

2. **The "empty" test wallet was not empty.**
   Case 3 first used `0x1111…1111` as a zero-balance wallet; the guard
   returned ALLOW — correctly, because that address actually holds ~458M
   USDT on-chain (verified by direct RPC). Fix: the case now uses a
   verified zero-balance address
   (`0x9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00`, balance 0).

3. **A hand-typed test address had 39 hex chars, not 40.**
   The zero-balance address above was first typed with 39 chars and the
   guard (correctly) rejected it as `INVALID_INPUT`. Fix: the address was
   corrected to 40 chars and its zero balance re-verified on-chain.

4. **BSC USDT has 18 decimals, not 6.**
   The first test amounts used `1000000` as "1 USDT" (Ethereum convention).
   On BSC, 1 USDT = 10^18 raw units, so the demo and tests now use
   `1000000000000000000` for 1 USDT and the demo help text says so.

5. **A candidate V3 router address had no code.**
   While curating the known-spender set, a remembered PancakeSwap V3 router
   address (`0x13f4EA83…`) was checked on-chain and found to have no code —
   it was rejected from the set. The set today contains only PancakeSwap
   Router v2, verified live.

## Known test sensitivities

- The tests depend on live BSC RPC and on the current on-chain state of
  the fixture addresses (Binance hot wallet balance, router code, the
  zero-balance wallet). If any fixture address changes state, the affected
  case will fail loudly rather than silently pass — that is intentional.
- Response times vary with RPC latency (observed 190 ms–2.1 s per request);
  the 8s fail-closed guard never fired during testing.
- The sample proof in `scripts/setup-circuit.sh` step 6 covers the
  unlimited-to-unknown-spender case and verifies against the exported
  `vk.json` (658 ms locally).
