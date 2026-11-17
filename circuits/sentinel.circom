// Sentinel — wallet & transaction guard.
// zkVerify Agent Games Season 01, Wildcard track.
//
// Checkable claim (sentinel-v1):
//   "Given the observed on-chain facts (encoded as bits), the verdict is
//    exactly the output of the published rule function."
//
// Inputs (all public signals, each a bit except verdict):
//   unlimited      — 1 if the approval amount is unlimited (>= 2^255, see README)
//   spenderZero    — 1 if the spender is the zero address
//   spenderNoCode  — 1 if the spender has no contract code (EOA / not a contract)
//   spenderUnknown  — 1 if the spender is a contract that is NOT in the
//                    curated known-spender set (see README "Why an allowlist").
//                    Every newly-deployed contract is unknown by definition;
//                    unknown spenders are REVIEW (or BLOCK if unlimited).
//   tokenNoCode    — 1 if the token address has no contract code
//   exceedsBalance — 1 if a bounded amount is larger than the wallet's token balance
//   verdict        — 0 = ALLOW, 1 = REVIEW, 2 = BLOCK
//
// Rule function (see README for the full rule set):
//   BLOCK  if spenderZero OR tokenNoCode OR exceedsBalance
//          OR (unlimited AND (spenderUnknown OR spenderNoCode))
//   REVIEW if (unlimited OR spenderNoCode OR spenderUnknown) AND NOT BLOCK
//   ALLOW  otherwise
//
// The circuit does NOT prove the RPC facts themselves (those come from the
// public BSC RPC and are independently checkable on-chain); it proves that
// the verdict follows from the facts by the published rule. When any fact
// is unknown (RPC error), no proof is produced — the response says so and
// the verdict is REVIEW (fail closed). See README "The zkVerify note".

pragma circom 2.0.0;

template Sentinel() {
    signal input unlimited;
    signal input spenderZero;
    signal input spenderNoCode;
    signal input spenderUnknown;
    signal input tokenNoCode;
    signal input exceedsBalance;
    signal input verdict;

    // Every fact flag must be a bit.
    unlimited * (unlimited - 1) === 0;
    spenderZero * (spenderZero - 1) === 0;
    spenderNoCode * (spenderNoCode - 1) === 0;
    spenderUnknown * (spenderUnknown - 1) === 0;
    tokenNoCode * (tokenNoCode - 1) === 0;
    exceedsBalance * (exceedsBalance - 1) === 0;

    // OR helper: or(a, b) = a + b - a*b
    // BLOCK = spenderZero OR tokenNoCode OR exceedsBalance
    //         OR (unlimited AND (spenderUnknown OR spenderNoCode))
    signal newOrNoCode <== spenderUnknown + spenderNoCode - spenderUnknown * spenderNoCode;
    signal unlimitedRisk <== unlimited * newOrNoCode;
    signal b1 <== spenderZero + tokenNoCode - spenderZero * tokenNoCode;
    signal b2 <== b1 + exceedsBalance - b1 * exceedsBalance;
    signal isBlock <== b2 + unlimitedRisk - b2 * unlimitedRisk;

    // REVIEW = (unlimited OR spenderNoCode OR spenderUnknown) AND NOT BLOCK
    signal r1 <== unlimited + spenderNoCode - unlimited * spenderNoCode;
    signal r2 <== r1 + spenderUnknown - r1 * spenderUnknown;
    signal isReview <== r2 * (1 - isBlock);

    // The verdict must be exactly 2*isBlock + isReview (0=ALLOW, 1=REVIEW, 2=BLOCK).
    verdict === 2 * isBlock + isReview;
}

component main { public [unlimited, spenderZero, spenderNoCode, spenderUnknown, tokenNoCode, exceedsBalance, verdict] } = Sentinel();
