# Sentinel — Wildcard submission pack

Copy-paste pack for the Agent Games Wildcard submission form.
Deadline: **21 Nov 2026 22:00 UTC**.
Fields required by the form (from the Wildcard page): Agent Link, Public
Endpoint, Use Case, Build Context, zkVerify (optional).

---

## Agent Link (public repository)

```
https://github.com/Cuanonli/sentinel
```

> PLACEHOLDER — replace with the real repo URL after the repo is created
> and pushed. The repo must be public and contain this project
> (`~/workspace/agent-games/wildcard-guard/`).

## Public Endpoint

```
https://<deployment>.vercel.app
```

> PLACEHOLDER — replace with the real Vercel deployment URL after deploy.
> The demo page is at `/` and the API at `POST /api/guard`.

---

## Use Case (paste as-is)

```
Sentinel is a wallet & transaction guard: it screens an ERC-20 approval
before you sign it and tells you, in plain words, whether it is safe —
ALLOW / REVIEW / BLOCK — with the exact checks that ran and a Groth16
proof that the verdict followed the published rule set.

The problem: unlimited token approvals are the most common way wallets get
drained. A user approves a random dApp "to save gas", the approval is
infinite, and weeks later the spender — or whoever controls it — empties
the wallet. The same pattern repeats with approvals to contracts deployed
minutes ago, approvals to addresses that are not contracts at all, and
approvals larger than the wallet's balance. Existing tools are reactive:
they show the damage after the approval exists. Sentinel is pre-signing.

Who it helps: everyday wallet users get a second opinion before signing an
approval, in words a non-developer can act on; AI agents that move funds
can call Sentinel before signing on a user's behalf (the verdict is
machine-readable, plus a proof); dApp and wallet developers get a drop-in
screening endpoint with a deterministic, published rule set.

What it actually does: POST an approval (wallet, token, spender, amount)
to the public endpoint and get a verdict with reason codes, the checks run
and their outcomes, the on-chain facts observed, and a Groth16 proof.
It is read-only — nothing is signed, nothing moves. Chain: BSC mainnet.
```

## Build Context (paste as-is)

```
Sentinel is a Node.js service (no framework) deployed as a Vercel
serverless function, in the same shape as our Proof Gatekeeper agent:
api/guard.js is the entry, lib/sentinel.mjs is the shared core (also used
by the local server), and a static demo page (public/index.html) lets
anyone paste an approval and see the verdict live.

How it works: (1) validate the input; (2) read on-chain facts from the
BSC public RPC with no API key — token code, spender code, the wallet's
token balance, and the current block; (3) apply the published rule set;
(4) generate a Groth16 proof (snarkjs, circuit circuits/sentinel.circom)
that the verdict follows from the facts; (5) return everything.

Key decisions:
- Fail closed. Any fact that cannot be observed (RPC error) means REVIEW,
  never ALLOW; unknown facts produce no proof and the response says so.
  An 8s guard fires before Vercel's 10s limit.
- The "newly deployed contract" check is a curated known-spender set, not
  an on-chain age check. We measured it: public BSC full nodes prune
  historical state, so eth_getCode fails with "missing trie node" even 128
  blocks back, the public archive endpoint times out, and BscScan's API
  returns a Cloudflare page here. So any contract outside the known set is
  treated as unknown — which includes every newly-deployed contract.
  The set is intentionally small (PancakeSwap Router v2 only, verified
  on-chain) and can only grow with an address + a public source.
- Unlimited means amount >= 2^255 (documented threshold); "max" is accepted.
- HMAC is optional: signed requests are verified when a secret is set,
  unsigned requests are served as public — this is a public demo endpoint,
  not a competition track with platform-signed tasks.
- v1 screens approvals only (BSC mainnet); transfers and other chains are
  out of scope and documented as such.

What it can and cannot do: it detects unlimited approvals, zero-address
spenders, non-contract tokens/spenders, unknown spenders, and amounts above
the wallet's balance, and proves the verdict followed the rule. It cannot
verify the RPC facts themselves (those are public and independently
checkable on-chain), it cannot judge a well-known contract's intent, and
it does not move funds or sign anything.
```

## zkVerify note (paste as-is)

```
Checkable claim (sentinel-v1): given the observed on-chain facts (encoded
as public signals), the verdict is exactly the output of the published
rule function. Circuit: circuits/sentinel.circom (Groth16, BN128, 14
non-linear constraints, 7 public signals: unlimited, spenderZero,
spenderNoCode, spenderUnknown, tokenNoCode, exceedsBalance, verdict;
0=ALLOW, 1=REVIEW, 2=BLOCK).

Every response with a complete fact set includes the Groth16 proof and its
public signals. The verification key is published in artifacts/vk.json
(SHA-256 e54fe9c7793e78c1439bff11a62952167743fe0a9442573baa834f71c0d67bed;
see artifacts/circuit-info.json for all artifact hashes). Verify offline:
npx snarkjs groth16 verify artifacts/vk.json signals.json proof.json.

The proof covers the rule application, not the RPC facts themselves — the
facts are public and independently checkable on-chain. When any fact is
unknown, no proof is produced and the response says so. The proving keys
come from a local single-contributor Powers of Tau ceremony (bn128, 2^12);
that is fine for a demo/competition entry but is documented as not a
production trusted setup (transcript kept in build/).
```

---

## Checklist before submitting

- [ ] GitHub repo created (public) and this project pushed to it
- [ ] Vercel deployment live (import the repo in the Vercel dashboard)
- [ ] Demo page opens at the deployment URL and a preset returns a verdict
- [ ] `GET /api/guard` returns `artifacts_ready: true`
- [ ] Replace the two PLACEHOLDER URLs above with the real repo + endpoint URLs
- [ ] Paste the Use Case, Build Context, and zkVerify texts above into the form
- [ ] Submit before **21 Nov 2026 22:00 UTC**
