#!/usr/bin/env bash
# Sentinel circuit setup — compile + trusted setup + verification key.
# Run from the project root:  bash scripts/setup-circuit.sh
#
# What it does:
#   1. Compiles circuits/sentinel.circom with circom 2.2.x
#      (download the binary first if needed:
#       curl -L -o /tmp/circom https://github.com/iden3/circom/releases/download/v2.2.2/circom-linux-amd64
#       chmod +x /tmp/circom)
#   2. Runs a small local Powers of Tau ceremony (bn128, 2^12) with a
#      single contribution, then a Groth16 setup and a second contribution.
#   3. Exports artifacts/vk.json and writes artifacts/circuit-info.json.
#   4. Verifies a sample proof against the exported verification key.
#
# NOTE: this is a single-contributor local ceremony. That is fine for a
# demo / competition entry (the claim is "the verdict followed the published
# rule", verified against the published vk.json), but it is NOT a production
# trusted setup. The ceremony transcript (the .ptau and .zkey files) is kept
# in build/ so anyone can re-run it.
#
# Requires: circom binary on PATH (or set CIRCOM_BIN), node + snarkjs
# installed (npm install), and no network (after circom is present).

set -euo pipefail
cd "$(dirname "$0")/.."

CIRCOM_BIN="${CIRCOM_BIN:-circom}"
SNARKJS="./node_modules/.bin/snarkjs"
BUILD_DIR="build"
ART_DIR="artifacts"

mkdir -p "$BUILD_DIR" "$ART_DIR"

echo "== 1. Compile circuit =="
"$CIRCOM_BIN" circuits/sentinel.circom --r1cs --wasm --sym -o "$BUILD_DIR"
ls -la "$BUILD_DIR"/sentinel.*

echo "== 2. Powers of Tau (bn128, 2^12) =="
"$SNARKJS" powersoftau new bn128 12 "$BUILD_DIR/pot12_0000.ptau" -v
"$SNARKJS" powersoftau contribute "$BUILD_DIR/pot12_0000.ptau" "$BUILD_DIR/pot12_0001.ptau" \
  --name="sentinel-ptau" -v -e="sentinel wildcard guard local ceremony"
"$SNARKJS" powersoftau prepare phase2 "$BUILD_DIR/pot12_0001.ptau" "$BUILD_DIR/pot12_final.ptau" -v

echo "== 3. Groth16 setup =="
"$SNARKJS" groth16 setup "$BUILD_DIR/sentinel.r1cs" "$BUILD_DIR/pot12_final.ptau" "$BUILD_DIR/sentinel_0000.zkey"
"$SNARKJS" zkey contribute "$BUILD_DIR/sentinel_0000.zkey" "$BUILD_DIR/sentinel_final.zkey" \
  --name="sentinel-zkey" -v -e="sentinel wildcard guard local ceremony"
"$SNARKJS" zkey export verificationkey "$BUILD_DIR/sentinel_final.zkey" "$ART_DIR/vk.json"

echo "== 4. Copy proving artifacts =="
cp "$BUILD_DIR/sentinel_js/sentinel.wasm" "$ART_DIR/sentinel.wasm"
cp "$BUILD_DIR/sentinel_final.zkey" "$ART_DIR/sentinel_final.zkey"

echo "== 5. Write circuit-info.json =="
node -e "
const fs = require('fs');
const crypto = require('crypto');
const vk = JSON.parse(fs.readFileSync('$ART_DIR/vk.json', 'utf8'));
const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const info = {
  name: 'sentinel',
  claim: 'sentinel-v1: verdict == rule(unlimited, spenderZero, spenderNoCode, spenderUnknown, tokenNoCode, exceedsBalance); verdict 0=ALLOW 1=REVIEW 2=BLOCK',
  curve: 'bn128',
  protocol: 'groth16',
  circuit: 'circuits/sentinel.circom',
  publicSignals: ['unlimited','spenderZero','spenderNoCode','spenderUnknown','tokenNoCode','exceedsBalance','verdict'],
  verificationKeySha256: sha('$ART_DIR/vk.json'),
  artifacts: {
    wasm: { file: 'artifacts/sentinel.wasm', sha256: sha('$ART_DIR/sentinel.wasm') },
    zkey: { file: 'artifacts/sentinel_final.zkey', sha256: sha('$ART_DIR/sentinel_final.zkey') },
    vk:   { file: 'artifacts/vk.json', sha256: sha('$ART_DIR/vk.json') }
  },
  setup: 'local single-contributor Powers of Tau (bn128, 2^12) + Groth16 setup; ceremony transcript in build/ (pot12_*.ptau, sentinel_0000.zkey). Suitable for a demo/competition entry, not a production trusted setup.'
};
fs.writeFileSync('$ART_DIR/circuit-info.json', JSON.stringify(info, null, 2) + '\n');
console.log(JSON.stringify(info, null, 2));
"

echo "== 6. Verify a sample proof =="
node -e "
const snarkjs = require('snarkjs');
const fs = require('fs');
(async () => {
  // Sample: unlimited approval to an unknown contract spender -> BLOCK (2)
  const input = { unlimited: 1, spenderZero: 0, spenderNoCode: 0, spenderUnknown: 1, tokenNoCode: 0, exceedsBalance: 0, verdict: 2 };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, '$ART_DIR/sentinel.wasm', '$ART_DIR/sentinel_final.zkey');
  const vk = JSON.parse(fs.readFileSync('$ART_DIR/vk.json', 'utf8'));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  console.log('sample proof publicSignals:', JSON.stringify(publicSignals));
  console.log('sample proof verifies:', ok);
  if (!ok) process.exit(1);
})();
"

echo "== DONE: artifacts in $ART_DIR =="
ls -la "$ART_DIR"
