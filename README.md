# Holder Testnet Subkey Contract

Version: `0.2.0-alpha.1`
Status: alpha, testnet only
App: `https://alpha.holder.bot`

## Purpose

This repository contains the NEAR smart contract used by Holder testnet to:
- register wallet-owned subkeys
- restrict those subkeys to allowed derivation paths per chain
- forward signing requests to the configured MPC signer contract
- store and enforce signer-scoped policy rules for selected transaction types

## Security review scope

Reviewers should focus on:
- authorization boundaries between root wallet control, subkeys, and delegated policy managers
- correctness of subkey registration and removal
- correctness of derivation-path allowlist enforcement
- correctness of signer policy storage and enforcement
- correctness of forwarding to the configured MPC contract
- privilege-escalation, replay, and policy-bypass risks
- migration safety for persisted state

## High-level trust model

This contract is one enforcement layer in a multi-layer system:
- the wallet/browser controls root authority and creates or removes subkeys
- the server performs pre-checks and orchestration for UX and monitoring
- the contract is intended to be the authoritative on-chain gate for deterministic policy checks
- the MPC signer contract produces signatures only after this contract accepts a request

The server is not intended to hold the wallet root private key.

## Current contract responsibilities

The contract currently supports:
- contract admin configuration
- wallet-scoped subkey registration with per-chain derivation path allowlists
- raw signing requests
- template-aware signing requests
- delegated policy-manager grants
- signer policy persistence keyed by wallet account plus subkey public key
- deterministic enforcement for supported Solana native transfer policy rules

Alpha chain scope is:
- `Solana`
- `Evm` for:
  - Ethereum
  - Base
  - Hedera

At the contract layer, the expected direction is a single `Evm` signing family rather than separate contract enums for Ethereum, Base, and Hedera. Chain-specific behavior is expected to be distinguished by template, network, and transaction payload fields rather than by separate signing enums.

## Server / contract interface relevant to review

The important interface assumptions are:

1. The server submits signing requests to this contract using a registered subkey or delegated policy manager.
2. The contract validates signer authority and allowed derivation path before forwarding to MPC.
3. For supported template-enforced requests, the server includes a policy memo carrying normalized intent and policy snapshot data.
4. The contract parses that policy memo and applies deterministic checks before forwarding the signing request.
5. The contract stores request results for polling and emits events for indexing.

This repository does not include the full wallet/server application. Review should assume:
- off-chain transaction construction happens outside the contract
- the contract must reject malformed, unauthorized, or policy-violating requests even if an off-chain component behaves incorrectly

## Current policy enforcement in scope

For supported transaction types, the current alpha policy model is intended to enforce:
- template match
- destination allowlist
- per-transaction native cap
- per-period native cap
- max transaction count per period

At present, the primary on-chain enforced transaction shape is Solana native transfer intent.

Near-term alpha product scope is:
- Solana
- Ethereum
- Base
- Hedera

Bitcoin is not part of the planned alpha release.

## External dependency

Primary external dependency:
- configured NEAR MPC signer contract via `mpc_contract_id`

The contract forwards signing requests to that MPC contract after local validation.

## Build

```bash
cargo build --target wasm32-unknown-unknown --release
```

Depending on toolchain output, a wasm re-emit / lowering step may still be required for NEAR runtime compatibility.

## Alpha note

This code is published for review in connection with the Holder alpha testnet system. It should be treated as pre-production code.
