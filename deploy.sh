#!/usr/bin/env bash
set -euo pipefail

# Simple deploy script for testnet
# Override via env: CONTRACT=..., OWNER=..., MPC=..., INIT_OR_MIGRATE=1

CONTRACT="${CONTRACT:-saif-near.testnet}"
OWNER="${OWNER:-saif-near.testnet}"
MPC="${MPC:-v1.signer-prod.testnet}"
INIT_OR_MIGRATE="${INIT_OR_MIGRATE:-0}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM="$ROOT_DIR/target/wasm32-unknown-unknown/release/safu_near_subkeys.wasm"
REEMIT_WASM="$ROOT_DIR/target/wasm32-unknown-unknown/release/safu_near_subkeys.reemit.wasm"
MVP_WASM="$ROOT_DIR/target/wasm32-unknown-unknown/release/safu_near_subkeys.mvp.wasm"

echo "Building wasm..."
cargo build --target wasm32-unknown-unknown --release --manifest-path "$ROOT_DIR/Cargo.toml"

if ! command -v wasm2wat >/dev/null 2>&1 || ! command -v wat2wasm >/dev/null 2>&1 || ! command -v wasm-opt >/dev/null 2>&1; then
  echo "Missing wasm2wat/wat2wasm (wabt). Please install wabt to re-emit wasm."
  exit 1
fi

echo "Re-emitting wasm for NEAR runtime compatibility..."
wasm2wat "$WASM" -o "$ROOT_DIR/target/wasm32-unknown-unknown/release/safu_near_subkeys.wat"
wat2wasm "$ROOT_DIR/target/wasm32-unknown-unknown/release/safu_near_subkeys.wat" -o "$REEMIT_WASM"
echo "Lowering wasm to MVP features..."
wasm-opt -O --mvp-features --signext-lowering --llvm-memory-copy-fill-lowering -o "$MVP_WASM" "$WASM"

echo "Deploying to $CONTRACT..."
near deploy --force "$CONTRACT" "$MVP_WASM"

if [[ "$INIT_OR_MIGRATE" == "1" ]]; then
  echo "Initializing/migrating contract..."
  near call "$CONTRACT" migrate "{\"owner_id\":\"$OWNER\",\"mpc_contract_id\":\"$MPC\"}" --accountId "$OWNER" || \
    near call "$CONTRACT" new "{\"owner_id\":\"$OWNER\",\"mpc_contract_id\":\"$MPC\"}" --accountId "$OWNER"
else
  echo "Skipping migrate/new (safe mode)."
  echo "Updating MPC endpoint via set_mpc..."
  near call "$CONTRACT" set_mpc "{\"mpc_contract_id\":\"$MPC\"}" --accountId "$OWNER"
fi

echo "Done. Contract: $CONTRACT Owner: $OWNER MPC: $MPC"
