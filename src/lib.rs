use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hex;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    bs58, env, near_bindgen, require, serde_json, AccountId, Gas, PanicOnDefault, Promise,
    PromiseResult, PublicKey,
};

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
const GAS_FOR_SIGN: Gas = Gas(20_000_000_000_000); // 20 Tgas for MPC callback placeholder
const GAS_FOR_CALLBACK: Gas = Gas(10_000_000_000_000); // 10 Tgas for on_sign_complete
const NATIVE_TOKEN: &str = "native";
const MPC_METHOD_SIGN_RAW: &str = "sign";
const MPC_METHOD_SIGN_TEMPLATE: &str = "sign_template";
const POLICY_MEMO_PREFIX: &str = "policy:";
const POLICY_MEMO_SEPARATOR: char = '|';
const SOLANA_SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
struct ContractPolicyInputMemo {
    pub template_id: String,
    pub template_params: serde_json::Value,
    pub policy_snapshot: Option<ContractPolicySnapshotMemo>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
struct ContractPolicySnapshotMemo {
    pub template_allowlist: Vec<String>,
    pub destination_allowlist: Vec<String>,
    pub rule: Option<ContractPolicyRuleMemo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
struct ContractPolicyRuleMemo {
    pub rule_id: String,
    pub asset_type: String,
    pub asset_id: String,
    pub max_per_tx_native: Option<serde_json::Value>,
    pub max_per_period_native: Option<serde_json::Value>,
    pub period_seconds: Option<u64>,
    pub max_tx_count_per_period: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSolanaNativeTransfer {
    pub from_public_key: String,
    pub destination: String,
    pub lamports: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum Chain {
    Solana,
    Evm,
    Bitcoin,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ChainPaths {
    pub chain: Chain,
    pub paths: Vec<String>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub chain: Chain,
    pub derivation_path: String,
    pub payload: Base64VecU8,
    pub memo: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub enum TxKind {
    SolanaNative,
    SolanaSpl,
    SolanaToken2022,
    EvmNative,
    EvmErc20,
    BitcoinSend,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TxTemplate {
    pub template_id: String,
    pub chain: Chain,
    pub kind: TxKind,
    pub allowed_tokens: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct TemplateSignRequest {
    pub template_id: String,
    pub chain: Chain,
    pub derivation_path: String,
    pub to: String,
    pub amount: U128,
    pub token_contract: Option<String>,
    pub symbol: Option<String>,
    pub evm_chain_id: Option<String>,
    pub memo: Option<String>,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct SignResult {
    pub request_id: String,
    pub ok: bool,
    pub payload: Option<Base64VecU8>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct ApiKeyPolicyV1 {
    pub version: String,
    pub template_id: String,
    pub asset_type: String,
    pub asset_id: Option<String>,
    pub max_per_tx_native: Option<String>,
    pub max_per_period_native: Option<String>,
    pub period_seconds: Option<u64>,
    pub max_tx_count_per_period: Option<u64>,
    pub allow_destinations: Vec<String>,
    pub period_start_unix_seconds: Option<u64>,
    pub spent_this_period_native: Option<String>,
    pub tx_count_this_period: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct PolicyManagerGrant {
    pub can_manage_policies: bool,
    pub can_manage_self_policy: bool,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct AllowedPaths {
    entries: Vec<ChainPaths>,
}

impl AllowedPaths {
    fn new(paths: Vec<ChainPaths>) -> Self {
        Self { entries: paths }
    }

    fn is_allowed(&self, chain: &Chain, derivation_path: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| &entry.chain == chain && entry.paths.iter().any(|p| p == derivation_path))
    }
}

fn key_type_for_chain(chain: &Chain) -> &'static str {
    match chain {
        Chain::Solana => "Eddsa",
        Chain::Evm => "Ecdsa",
        Chain::Bitcoin => "Ecdsa",
    }
}

fn domain_id_for_chain(chain: &Chain) -> u8 {
    match chain {
        Chain::Solana => 1,
        Chain::Evm => 0,
        Chain::Bitcoin => 0,
    }
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct Contract {
    owner_id: AccountId,
    mpc_contract_id: AccountId,
    /// Keyed by "{account_id}|{public_key}"
    subkeys: LookupMap<String, AllowedPaths>,
    /// Index of subkeys per account for listing
    subkey_index: LookupMap<AccountId, Vec<String>>,
    /// Keyed by "{chain}|{template_id}"
    templates: LookupMap<String, TxTemplate>,
    /// Keyed by "{chain}|{token_contract_or_native}"
    token_caps: LookupMap<String, u128>,
    /// Keyed by request_id
    sign_results: LookupMap<String, SignResult>,
    /// Keyed by "{account_id}|{public_key}"
    policy_managers: LookupMap<String, PolicyManagerGrant>,
    /// Keyed by "{account_id}|{public_key}"
    api_key_policies: LookupMap<String, ApiKeyPolicyV1>,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct ContractV0 {
    owner_id: AccountId,
    mpc_contract_id: AccountId,
    subkeys: LookupMap<String, AllowedPaths>,
    subkey_index: LookupMap<AccountId, Vec<String>>,
    templates: LookupMap<String, TxTemplate>,
    token_caps: LookupMap<String, u128>,
    sign_results: LookupMap<String, SignResult>,
}

#[derive(BorshDeserialize, BorshSerialize)]
struct ContractV1 {
    owner_id: AccountId,
    mpc_contract_id: AccountId,
    subkeys: LookupMap<String, AllowedPaths>,
    subkey_index: LookupMap<AccountId, Vec<String>>,
    templates: LookupMap<String, TxTemplate>,
    token_caps: LookupMap<String, u128>,
    sign_results: LookupMap<String, SignResult>,
    api_key_policies: LookupMap<String, ApiKeyPolicyV1>,
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(owner_id: AccountId, mpc_contract_id: AccountId) -> Self {
        require!(!env::state_exists(), "already initialized");
        Self {
            owner_id,
            mpc_contract_id,
            subkeys: LookupMap::new(b"s"),
            subkey_index: LookupMap::new(b"i"),
            templates: LookupMap::new(b"t"),
            token_caps: LookupMap::new(b"c"),
            sign_results: LookupMap::new(b"r"),
            policy_managers: LookupMap::new(b"g"),
            api_key_policies: LookupMap::new(b"p"),
        }
    }

    /// Migration helper for upgrades from the minimal stub (reinitializes collections).
    #[init(ignore_state)]
    pub fn migrate(owner_id: AccountId, mpc_contract_id: AccountId) -> Self {
        if let Some(old_state) = env::state_read::<ContractV1>() {
            return Self {
                owner_id: old_state.owner_id,
                mpc_contract_id: old_state.mpc_contract_id,
                subkeys: old_state.subkeys,
                subkey_index: old_state.subkey_index,
                templates: old_state.templates,
                token_caps: old_state.token_caps,
                sign_results: old_state.sign_results,
                policy_managers: LookupMap::new(b"g"),
                api_key_policies: old_state.api_key_policies,
            };
        }

        if let Some(old_state) = env::state_read::<ContractV0>() {
            return Self {
                owner_id: old_state.owner_id,
                mpc_contract_id: old_state.mpc_contract_id,
                subkeys: old_state.subkeys,
                subkey_index: old_state.subkey_index,
                templates: old_state.templates,
                token_caps: old_state.token_caps,
                sign_results: old_state.sign_results,
                policy_managers: LookupMap::new(b"g"),
                api_key_policies: LookupMap::new(b"p"),
            };
        }

        Self {
            owner_id,
            mpc_contract_id,
            subkeys: LookupMap::new(b"s"),
            subkey_index: LookupMap::new(b"i"),
            templates: LookupMap::new(b"t"),
            token_caps: LookupMap::new(b"c"),
            sign_results: LookupMap::new(b"r"),
            policy_managers: LookupMap::new(b"g"),
            api_key_policies: LookupMap::new(b"p"),
        }
    }

    /// Add a subkey for the caller with allowed derivation paths per chain.
    pub fn add_subkey(&mut self, public_key: PublicKey, derivation_paths: Vec<ChainPaths>) {
        self.assert_direct_call();
        // assert_direct_call() rejects cross-contract invocations and prevents relay/proxy attacks.
        // we already have the identity of the caller from the runtime environment via `#[near_bindgen]` macro
        let caller = env::predecessor_account_id();
        // NEAR runtime guarantees that `predecessor_account_id()` reflects the true transaction signer
        Self::validate_paths(&derivation_paths);
        let pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &pk);
        self.subkeys
            .insert(&storage_key, &AllowedPaths::new(derivation_paths.clone()));
        self.push_index(&caller, pk.clone());
        Self::log_event(
            "subkey_added",
            serde_json::json!({ "account_id": caller, "public_key": pk, "paths": derivation_paths }),
        );
    }

    /// Update derivation paths for an existing subkey (caller-scoped).
    pub fn set_subkey_paths(&mut self, public_key: PublicKey, derivation_paths: Vec<ChainPaths>) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        Self::validate_paths(&derivation_paths);
        let pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &pk);
        require!(self.subkeys.get(&storage_key).is_some(), "subkey not found");
        self.subkeys
            .insert(&storage_key, &AllowedPaths::new(derivation_paths.clone()));
        Self::log_event(
            "subkey_paths_set",
            serde_json::json!({ "account_id": caller, "public_key": pk, "paths": derivation_paths }),
        );
    }

    /// Remove a subkey for the caller.
    pub fn remove_subkey(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &pk);
        require!(
            self.subkeys.remove(&storage_key).is_some(),
            "subkey not found"
        );
        self.drop_from_index(&caller, &pk);
        Self::log_event(
            "subkey_removed",
            serde_json::json!({ "account_id": caller, "public_key": pk }),
        );
    }

    /// List subkeys owned by the given account (view).
    pub fn list_subkeys(&self, account_id: AccountId) -> Vec<String> {
        self.subkey_index.get(&account_id).unwrap_or_default()
    }

    /// Get allowed derivation paths for a specific subkey owned by the caller.
    pub fn get_subkey_paths(&self, public_key: PublicKey) -> Option<Vec<ChainPaths>> {
        let caller = env::predecessor_account_id();
        let pk = Self::pk_to_string(&public_key);
        self.subkeys
            .get(&Self::compose_key(&caller, &pk))
            .map(|p| p.entries)
    }

    /// Main entry: request an MPC signature. Must be signed by a registered subkey of the caller.
    #[payable]
    pub fn request_sign(&mut self, request: SignRequest) -> Promise {
        self.assert_direct_call();
        require!(!request.payload.0.is_empty(), "invalid payload size");
        require!(
            request.payload.0.len() <= MAX_PAYLOAD_BYTES,
            "payload too large"
        );
        Self::validate_path(&request.derivation_path);
        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let SignRequest {
            chain,
            derivation_path,
            payload,
            memo,
        } = request;
        self.enforce_contract_policy_for_raw_request(&chain, &payload.0, memo.as_deref());

        Self::log_event(
            "sign_request",
            serde_json::json!({
                "account_id": caller,
                "public_key": signer_pk,
                "chain": chain,
                "derivation_path": derivation_path,
                "memo": memo,
                "payload_len": payload.0.len()
            }),
        );

        let payload_hex = hex::encode(&payload.0);
        let key_type = key_type_for_chain(&chain);
        let signer_path = format!("{}:{}", caller, derivation_path);
        let args = serde_json::json!({
            "request": {
                "payload_v2": { key_type: payload_hex },
                "path": signer_path,
                "domain_id": domain_id_for_chain(&chain),
            }
        });

        Promise::new(self.mpc_contract_id.clone()).function_call(
            MPC_METHOD_SIGN_RAW.to_string(),
            args.to_string().into_bytes(),
            1,
            GAS_FOR_SIGN,
        )
    }

    /// Request an MPC signature with a request_id (stores result for polling).
    #[payable]
    pub fn request_sign_v2(&mut self, request_id: String, request: SignRequest) -> Promise {
        self.assert_direct_call();
        self.assert_new_request_id(&request_id);
        require!(!request.payload.0.is_empty(), "invalid payload size");
        require!(
            request.payload.0.len() <= MAX_PAYLOAD_BYTES,
            "payload too large"
        );
        Self::validate_path(&request.derivation_path);
        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let SignRequest {
            chain,
            derivation_path,
            payload,
            memo,
        } = request;
        self.enforce_contract_policy_for_raw_request(&chain, &payload.0, memo.as_deref());

        let payload_hex = hex::encode(&payload.0);
        let key_type = key_type_for_chain(&chain);
        let signer_path = format!("{}:{}", caller, derivation_path);
        let args = serde_json::json!({
            "request": {
                "payload_v2": { key_type: payload_hex },
                "path": signer_path,
                "domain_id": domain_id_for_chain(&chain),
            }
        });

        Promise::new(self.mpc_contract_id.clone())
            .function_call(
                MPC_METHOD_SIGN_RAW.to_string(),
                args.to_string().into_bytes(),
                1,
                GAS_FOR_SIGN,
            )
            .then(
                Promise::new(env::current_account_id()).function_call(
                    "on_sign_complete".to_string(),
                    serde_json::json!({ "request_id": request_id })
                        .to_string()
                        .into_bytes(),
                    0,
                    GAS_FOR_CALLBACK,
                ),
            )
    }

    /// Owner-only: set or update a template definition.
    pub fn set_template(&mut self, template: TxTemplate) {
        self.assert_owner();
        require!(!template.template_id.is_empty(), "template_id required");
        if let Some(tokens) = &template.allowed_tokens {
            for token in tokens {
                require!(!token.is_empty(), "empty token in allowlist");
            }
        }
        let key = Self::template_key(&template.chain, &template.template_id);
        self.templates.insert(&key, &template);
        Self::log_event("template_set", serde_json::json!({ "template": template }));
    }

    /// Owner-only: remove a template.
    pub fn remove_template(&mut self, chain: Chain, template_id: String) {
        self.assert_owner();
        let key = Self::template_key(&chain, &template_id);
        require!(self.templates.remove(&key).is_some(), "template not found");
        Self::log_event(
            "template_removed",
            serde_json::json!({ "chain": chain, "template_id": template_id }),
        );
    }

    /// Owner-only: set max amount cap for a token (or native).
    pub fn set_token_cap(
        &mut self,
        chain: Chain,
        token_contract: Option<String>,
        max_amount: U128,
    ) {
        self.assert_owner();
        let token = token_contract.unwrap_or_else(|| NATIVE_TOKEN.to_string());
        require!(!token.is_empty(), "token required");
        let key = Self::cap_key(&chain, &token);
        self.token_caps.insert(&key, &max_amount.0);
        Self::log_event(
            "token_cap_set",
            serde_json::json!({ "chain": chain, "token_contract": token, "max_amount": max_amount }),
        );
    }

    /// Owner-only: remove max amount cap.
    pub fn remove_token_cap(&mut self, chain: Chain, token_contract: Option<String>) {
        self.assert_owner();
        let token = token_contract.unwrap_or_else(|| NATIVE_TOKEN.to_string());
        let key = Self::cap_key(&chain, &token);
        require!(self.token_caps.remove(&key).is_some(), "cap not found");
        Self::log_event(
            "token_cap_removed",
            serde_json::json!({ "chain": chain, "token_contract": token }),
        );
    }

    pub fn get_template(&self, chain: Chain, template_id: String) -> Option<TxTemplate> {
        self.templates
            .get(&Self::template_key(&chain, &template_id))
    }

    pub fn get_token_cap(&self, chain: Chain, token_contract: Option<String>) -> Option<U128> {
        let token = token_contract.unwrap_or_else(|| NATIVE_TOKEN.to_string());
        self.token_caps
            .get(&Self::cap_key(&chain, &token))
            .map(U128)
    }

    /// Request a templated sign; enforces template + token caps before forwarding.
    pub fn request_template_sign(&self, request: TemplateSignRequest) -> Promise {
        self.assert_direct_call();
        require!(!request.template_id.is_empty(), "template_id required");
        require!(
            !request.derivation_path.is_empty(),
            "derivation_path required"
        );
        Self::validate_path(&request.derivation_path);
        require!(!request.to.is_empty(), "to required");

        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let template = self
            .templates
            .get(&Self::template_key(&request.chain, &request.template_id))
            .unwrap_or_else(|| env::panic_str("template not found"));
        require!(template.chain == request.chain, "template chain mismatch");

        Self::validate_template_request(&template, &request);

        let token_contract = request
            .token_contract
            .clone()
            .unwrap_or_else(|| NATIVE_TOKEN.to_string());
        let cap_key = Self::cap_key(&request.chain, &token_contract);
        if let Some(max_amount) = self.token_caps.get(&cap_key) {
            require!(request.amount.0 <= max_amount, "amount exceeds cap");
        }

        Self::log_event(
            "template_sign_request",
            serde_json::json!({
                "account_id": caller,
                "public_key": signer_pk,
                "template_id": request.template_id,
                "chain": request.chain,
                "kind": template.kind,
                "to": request.to,
                "amount": request.amount,
                "token_contract": request.token_contract,
                "symbol": request.symbol,
                "evm_chain_id": request.evm_chain_id,
                "memo": request.memo
            }),
        );

        let signer_path = format!("{}:{}", caller, request.derivation_path);
        let args = serde_json::json!({
            "request": {
                "caller": caller,
                "template_id": request.template_id,
                "chain": request.chain,
                "kind": template.kind,
                "derivation_path": signer_path,
                "to": request.to,
                "amount": request.amount,
                "token_contract": request.token_contract,
                "symbol": request.symbol,
                "evm_chain_id": request.evm_chain_id,
                "memo": request.memo,
            }
        });

        Promise::new(self.mpc_contract_id.clone()).function_call(
            MPC_METHOD_SIGN_TEMPLATE.to_string(),
            args.to_string().into_bytes(),
            1,
            GAS_FOR_SIGN,
        )
    }

    /// Request a templated sign with a request_id (stores result for polling).
    pub fn request_template_sign_v2(
        &mut self,
        request_id: String,
        request: TemplateSignRequest,
    ) -> Promise {
        self.assert_direct_call();
        self.assert_new_request_id(&request_id);
        require!(!request.template_id.is_empty(), "template_id required");
        require!(
            !request.derivation_path.is_empty(),
            "derivation_path required"
        );
        Self::validate_path(&request.derivation_path);
        require!(!request.to.is_empty(), "to required");

        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let storage_key = Self::compose_key(&caller, &signer_pk);
        let allowed = self
            .subkeys
            .get(&storage_key)
            .unwrap_or_else(|| env::panic_str("unauthorized subkey"));
        require!(
            allowed.is_allowed(&request.chain, &request.derivation_path),
            "derivation path not allowed"
        );

        let template = self
            .templates
            .get(&Self::template_key(&request.chain, &request.template_id))
            .unwrap_or_else(|| env::panic_str("template not found"));
        require!(template.chain == request.chain, "template chain mismatch");

        Self::validate_template_request(&template, &request);

        let token_contract = request
            .token_contract
            .clone()
            .unwrap_or_else(|| NATIVE_TOKEN.to_string());
        let cap_key = Self::cap_key(&request.chain, &token_contract);
        if let Some(max_amount) = self.token_caps.get(&cap_key) {
            require!(request.amount.0 <= max_amount, "amount exceeds cap");
        }

        let signer_path = format!("{}:{}", caller, request.derivation_path);
        let args = serde_json::json!({
            "request": {
                "caller": caller,
                "template_id": request.template_id,
                "chain": request.chain,
                "kind": template.kind,
                "derivation_path": signer_path,
                "to": request.to,
                "amount": request.amount,
                "token_contract": request.token_contract,
                "symbol": request.symbol,
                "evm_chain_id": request.evm_chain_id,
                "memo": request.memo,
            }
        });

        Promise::new(self.mpc_contract_id.clone())
            .function_call(
                MPC_METHOD_SIGN_TEMPLATE.to_string(),
                args.to_string().into_bytes(),
                1,
                GAS_FOR_SIGN,
            )
            .then(
                Promise::new(env::current_account_id()).function_call(
                    "on_sign_complete".to_string(),
                    serde_json::json!({ "request_id": request_id })
                        .to_string()
                        .into_bytes(),
                    0,
                    GAS_FOR_CALLBACK,
                ),
            )
    }

    /// View: get stored sign result for a request_id.
    pub fn get_sign_result(&self, request_id: String) -> Option<SignResult> {
        self.sign_results.get(&request_id)
    }

    /// Root-wallet-only: grant policy-manager authority to a registered subkey.
    pub fn grant_policy_manager(
        &mut self,
        public_key: PublicKey,
        can_manage_self_policy: Option<bool>,
    ) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &target_pk);
        require!(self.subkeys.get(&storage_key).is_some(), "subkey not found");

        let grant = PolicyManagerGrant {
            can_manage_policies: true,
            can_manage_self_policy: can_manage_self_policy.unwrap_or(false),
        };
        self.policy_managers.insert(&storage_key, &grant);
        Self::log_event(
            "policy_manager_granted",
            serde_json::json!({
                "account_id": caller,
                "public_key": target_pk,
                "grant": grant
            }),
        );
    }

    /// Root-wallet-only: revoke policy-manager authority from a registered subkey.
    pub fn revoke_policy_manager(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        let storage_key = Self::compose_key(&caller, &target_pk);
        require!(
            self.policy_managers.remove(&storage_key).is_some(),
            "policy manager not found"
        );
        Self::log_event(
            "policy_manager_revoked",
            serde_json::json!({ "account_id": caller, "public_key": target_pk }),
        );
    }

    pub fn get_policy_manager(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<PolicyManagerGrant> {
        let target_pk = Self::pk_to_string(&public_key);
        self.policy_managers
            .get(&Self::compose_key(&account_id, &target_pk))
    }

    /// Role-gated: set or update persisted policy for a signer subkey.
    pub fn set_signer_policy(&mut self, public_key: PublicKey, policy: ApiKeyPolicyV1) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.assert_can_manage_policy(&caller, &target_pk);
        self.upsert_signer_policy(&caller, &target_pk, policy, "signer_policy_set");
    }

    /// Root/browser path: direct policy write for a signer subkey.
    pub fn owner_set_signer_policy(&mut self, public_key: PublicKey, policy: ApiKeyPolicyV1) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.upsert_signer_policy(&caller, &target_pk, policy, "owner_signer_policy_set");
    }

    /// Role-gated: remove persisted policy for a signer subkey.
    pub fn remove_signer_policy(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.assert_can_manage_policy(&caller, &target_pk);
        self.drop_signer_policy(&caller, &target_pk, "signer_policy_removed");
    }

    /// Root/browser path: direct policy removal for a signer subkey.
    pub fn owner_remove_signer_policy(&mut self, public_key: PublicKey) {
        self.assert_direct_call();
        let caller = env::predecessor_account_id();
        let target_pk = Self::pk_to_string(&public_key);
        self.drop_signer_policy(&caller, &target_pk, "owner_signer_policy_removed");
    }

    pub fn get_signer_policy(&self, account_id: AccountId, public_key: PublicKey) -> Option<ApiKeyPolicyV1> {
        let target_pk = Self::pk_to_string(&public_key);
        self.api_key_policies
            .get(&Self::compose_key(&account_id, &target_pk))
    }

    /// Owner-only: remove stored sign results by request_id.
    pub fn cleanup_results(&mut self, request_ids: Vec<String>) -> u32 {
        self.assert_owner();
        let total = request_ids.len() as u32;
        let mut removed = 0u32;
        for request_id in request_ids {
            if self.sign_results.remove(&request_id).is_some() {
                removed += 1;
            }
        }
        Self::log_event(
            "cleanup_results",
            serde_json::json!({
                "removed": removed,
                "total": total
            }),
        );
        removed
    }

    #[private]
    pub fn on_sign_complete(&mut self, request_id: String) -> SignResult {
        let result = match env::promise_result(0) {
            PromiseResult::Successful(bytes) => SignResult {
                request_id: request_id.clone(),
                ok: true,
                payload: if bytes.is_empty() {
                    None
                } else {
                    Some(Base64VecU8(bytes))
                },
                error: None,
            },
            PromiseResult::Failed => SignResult {
                request_id: request_id.clone(),
                ok: false,
                payload: None,
                error: Some("mpc sign failed".to_string()),
            },
            PromiseResult::NotReady => env::panic_str("promise not ready"),
        };
        self.sign_results.insert(&request_id, &result);
        Self::log_event(
            "sign_result",
            serde_json::json!({
                "request_id": request_id,
                "ok": result.ok,
                "has_payload": result.payload.is_some(),
                "error": result.error
            }),
        );
        result
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn get_mpc(&self) -> AccountId {
        self.mpc_contract_id.clone()
    }

    /// Owner-only: update MPC endpoint without resetting contract state.
    pub fn set_mpc(&mut self, mpc_contract_id: AccountId) {
        self.assert_owner();
        self.mpc_contract_id = mpc_contract_id.clone();
        Self::log_event(
            "mpc_updated",
            serde_json::json!({
                "mpc_contract_id": mpc_contract_id
            }),
        );
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    fn assert_new_request_id(&self, request_id: &str) {
        require!(!request_id.is_empty(), "request_id required");
        // NEAR cross-contract calls complete in a later block. Without this check,
        // a caller could submit the same `request_id` a second time before the first
        // callback has written its result.
        require!(
            self.sign_results.get(&request_id.to_string()).is_none(),
            "request_id already used"
        );
    }

    fn assert_direct_call(&self) {
        require!(
            env::predecessor_account_id() == env::signer_account_id(),
            "cross-contract calls not allowed"
        );
    }

    fn assert_can_manage_policy(&self, caller: &AccountId, target_pk: &str) {
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        let signer_storage_key = Self::compose_key(caller, &signer_pk);
        if self.subkeys.get(&signer_storage_key).is_none() {
            return;
        }

        let Some(grant) = self.policy_managers.get(&signer_storage_key) else {
            env::panic_str("policy write not allowed");
        };

        if grant.can_manage_policies {
            return;
        }
        if grant.can_manage_self_policy && signer_pk == target_pk {
            return;
        }

        env::panic_str("policy write not allowed");
    }

    fn upsert_signer_policy(
        &mut self,
        caller: &AccountId,
        target_pk: &str,
        policy: ApiKeyPolicyV1,
        event: &str,
    ) {
        let storage_key = Self::compose_key(caller, target_pk);
        require!(self.subkeys.get(&storage_key).is_some(), "subkey not found");
        let normalized = Self::normalize_api_key_policy(policy);
        self.api_key_policies.insert(&storage_key, &normalized);
        Self::log_event(
            event,
            serde_json::json!({
                "account_id": caller,
                "public_key": target_pk,
                "template_id": normalized.template_id,
                "asset_type": normalized.asset_type,
                "asset_id": normalized.asset_id,
                "period_seconds": normalized.period_seconds,
                "max_tx_count_per_period": normalized.max_tx_count_per_period,
                "allow_destinations": normalized.allow_destinations
            }),
        );
    }

    fn drop_signer_policy(&mut self, caller: &AccountId, target_pk: &str, event: &str) {
        let storage_key = Self::compose_key(caller, target_pk);
        require!(
            self.api_key_policies.remove(&storage_key).is_some(),
            "policy not found"
        );
        Self::log_event(
            event,
            serde_json::json!({ "account_id": caller, "public_key": target_pk }),
        );
    }

    fn compose_key(account_id: &AccountId, pk: &str) -> String {
        format!("{}|{}", account_id, pk)
    }

    fn template_key(chain: &Chain, template_id: &str) -> String {
        format!("{}|{}", Self::chain_key(chain), template_id)
    }

    fn cap_key(chain: &Chain, token_contract: &str) -> String {
        format!("{}|{}", Self::chain_key(chain), token_contract)
    }

    fn chain_key(chain: &Chain) -> &'static str {
        match chain {
            Chain::Solana => "solana",
            Chain::Evm => "evm",
            Chain::Bitcoin => "bitcoin",
        }
    }

    fn pk_to_string(pk: &PublicKey) -> String {
        bs58::encode(pk.as_bytes()).into_string()
    }

    fn validate_paths(paths: &[ChainPaths]) {
        require!(!paths.is_empty(), "paths required");
        for entry in paths {
            require!(!entry.paths.is_empty(), "path list cannot be empty");
            for p in &entry.paths {
                Self::validate_path(p);
            }
        }
        // ensure unique chain per entry
        let mut seen = std::collections::HashSet::new();
        for entry in paths {
            require!(
                seen.insert(format!("{:?}", entry.chain)),
                "duplicate chain entry"
            );
        }
    }

    fn validate_path(path: &str) {
        require!(!path.is_empty(), "empty derivation path");
        require!(
            !path.contains(':'),
            "derivation path contains invalid separator"
        );
    }

    fn validate_template_request(template: &TxTemplate, request: &TemplateSignRequest) {
        match template.kind {
            TxKind::SolanaNative | TxKind::EvmNative | TxKind::BitcoinSend => {
                require!(request.token_contract.is_none(), "token not allowed");
            }
            TxKind::SolanaSpl | TxKind::SolanaToken2022 | TxKind::EvmErc20 => {
                require!(request.token_contract.is_some(), "token contract required");
            }
        }
        if let Some(allowed) = &template.allowed_tokens {
            if let Some(token) = &request.token_contract {
                require!(allowed.contains(token), "token not allowed");
            } else {
                require!(false, "token contract required");
            }
        }
    }

    fn enforce_contract_policy_for_raw_request(
        &mut self,
        chain: &Chain,
        payload: &[u8],
        memo: Option<&str>,
    ) {
        let Some(memo_text) = memo else {
            return;
        };
        let Some(encoded_payload) = Self::extract_policy_memo_payload(memo_text) else {
            return;
        };
        let policy = Self::decode_contract_policy_memo(encoded_payload);
        match (chain, policy.template_id.as_str()) {
            (Chain::Solana, "sol_native_transfer_v1") => {
                self.enforce_solana_native_policy(payload, &policy);
            }
            _ => {
                // Raw-path policy enforcement is intentionally limited to verifiable payload
                // types until more chain/template parsers land.
            }
        }
    }

    fn extract_policy_memo_payload(memo: &str) -> Option<&str> {
        if !memo.starts_with(POLICY_MEMO_PREFIX) {
            return None;
        }
        let raw = &memo[POLICY_MEMO_PREFIX.len()..];
        Some(raw.split(POLICY_MEMO_SEPARATOR).next().unwrap_or(raw))
    }

    fn decode_contract_policy_memo(encoded: &str) -> ContractPolicyInputMemo {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .unwrap_or_else(|_| env::panic_str("invalid_policy_memo"));
        serde_json::from_slice::<ContractPolicyInputMemo>(&bytes)
            .unwrap_or_else(|_| env::panic_str("invalid_policy_memo"))
    }

    fn enforce_solana_native_policy(&mut self, payload: &[u8], policy: &ContractPolicyInputMemo) {
        let parsed =
            Self::parse_solana_native_transfer(payload).unwrap_or_else(|_| env::panic_str("policy_payload_mismatch"));
        let expected_from = Self::json_string_field(&policy.template_params, "fromPublicKey")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_destination = Self::json_string_field(&policy.template_params, "destination")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_amount = Self::json_string_field(&policy.template_params, "amount")
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));
        let expected_lamports = Self::parse_sol_amount_to_lamports(&expected_amount)
            .unwrap_or_else(|| env::panic_str("policy_payload_mismatch"));

        require!(parsed.from_public_key == expected_from, "policy_payload_mismatch");
        require!(parsed.destination == expected_destination, "policy_payload_mismatch");
        require!(parsed.lamports == expected_lamports, "policy_payload_mismatch");

        if let Some(snapshot) = &policy.policy_snapshot {
            if !snapshot.template_allowlist.is_empty() {
                require!(
                    snapshot
                        .template_allowlist
                        .iter()
                        .any(|item| item == &policy.template_id),
                    "template_not_allowed"
                );
            }

            if !snapshot.destination_allowlist.is_empty() {
                require!(
                    snapshot
                        .destination_allowlist
                        .iter()
                        .any(|item| item == &parsed.destination),
                    "destination_not_allowed"
                );
            }

            if let Some(rule) = &snapshot.rule {
                let asset_type = rule.asset_type.trim().to_lowercase();
                if asset_type == "native" {
                    if let Some(max_lamports) =
                        Self::policy_native_cap_to_lamports(rule.max_per_tx_native.as_ref())
                    {
                        require!(parsed.lamports <= max_lamports, "limit_per_tx_native_exceeded");
                    }
                }
            }
        }

        let caller = env::predecessor_account_id();
        let signer_pk = Self::pk_to_string(&env::signer_account_pk());
        self.enforce_persisted_api_key_policy(&caller, &signer_pk, &policy.template_id, &parsed);
    }

    fn enforce_persisted_api_key_policy(
        &mut self,
        account_id: &AccountId,
        signer_public_key: &str,
        template_id: &str,
        parsed: &ParsedSolanaNativeTransfer,
    ) {
        let storage_key = Self::compose_key(account_id, signer_public_key);
        let mut policy = match self.api_key_policies.get(&storage_key) {
            Some(policy) => policy,
            None => return,
        };

        require!(policy.template_id == template_id, "template_not_allowed");

        if !policy.allow_destinations.is_empty() {
            require!(
                policy
                    .allow_destinations
                    .iter()
                    .any(|item| item == &parsed.destination),
                "destination_not_allowed"
            );
        }

        if let Some(max_lamports) =
            Self::optional_string_amount_to_lamports(policy.max_per_tx_native.as_ref())
        {
            require!(parsed.lamports <= max_lamports, "limit_per_tx_native_exceeded");
        }

        let max_per_period_lamports =
            Self::optional_string_amount_to_lamports(policy.max_per_period_native.as_ref());
        let max_tx_count_per_period = policy.max_tx_count_per_period;
        if max_per_period_lamports.is_none() && max_tx_count_per_period.is_none() {
            return;
        }

        let period_seconds = policy.period_seconds.unwrap_or(0);
        require!(period_seconds > 0, "policy_check_failed");

        let now_seconds = env::block_timestamp() / 1_000_000_000;
        let window_start = now_seconds - (now_seconds % period_seconds);
        if policy.period_start_unix_seconds != Some(window_start) {
            policy.period_start_unix_seconds = Some(window_start);
            policy.spent_this_period_native = Some("0".to_string());
            policy.tx_count_this_period = Some(0);
        }

        let current_spent =
            Self::optional_string_amount_to_lamports(policy.spent_this_period_native.as_ref())
                .unwrap_or(0);
        let next_spent = current_spent
            .checked_add(parsed.lamports)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));

        if let Some(max_lamports) = max_per_period_lamports {
            require!(
                next_spent <= max_lamports,
                "limit_per_period_native_exceeded"
            );
        }

        let current_tx_count = policy.tx_count_this_period.unwrap_or(0);
        let next_tx_count = current_tx_count
            .checked_add(1)
            .unwrap_or_else(|| env::panic_str("policy_check_failed"));
        if let Some(max_tx_count) = max_tx_count_per_period {
            require!(next_tx_count <= max_tx_count, "limit_tx_count_exceeded");
        }

        policy.period_start_unix_seconds = Some(window_start);
        policy.spent_this_period_native = Some(Self::lamports_to_sol_amount_string(next_spent));
        policy.tx_count_this_period = Some(next_tx_count);
        self.api_key_policies.insert(&storage_key, &policy);
    }

    fn json_string_field(value: &serde_json::Value, key: &str) -> Option<String> {
        value.get(key)?.as_str().map(|item| item.to_string())
    }

    fn policy_native_cap_to_lamports(value: Option<&serde_json::Value>) -> Option<u64> {
        let raw = value?;
        match raw {
            serde_json::Value::String(inner) => Self::parse_sol_amount_to_lamports(inner),
            serde_json::Value::Number(inner) => Self::parse_sol_amount_to_lamports(&inner.to_string()),
            _ => None,
        }
    }

    fn optional_string_amount_to_lamports(value: Option<&String>) -> Option<u64> {
        value
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .and_then(Self::parse_sol_amount_to_lamports)
    }

    fn parse_sol_amount_to_lamports(value: &str) -> Option<u64> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }
        let mut parts = trimmed.split('.');
        let whole = parts.next()?;
        let frac = parts.next();
        if parts.next().is_some() {
            return None;
        }
        if !whole.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let mut lamports = whole.parse::<u64>().ok()?.checked_mul(1_000_000_000)?;
        if let Some(frac_part) = frac {
            if frac_part.len() > 9 || !frac_part.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let mut padded = frac_part.to_string();
            while padded.len() < 9 {
                padded.push('0');
            }
            lamports = lamports.checked_add(padded.parse::<u64>().ok()?)?;
        }
        Some(lamports)
    }

    fn lamports_to_sol_amount_string(lamports: u64) -> String {
        let whole = lamports / 1_000_000_000;
        let frac = lamports % 1_000_000_000;
        if frac == 0 {
            return whole.to_string();
        }
        let mut frac_string = format!("{:09}", frac);
        while frac_string.ends_with('0') {
            frac_string.pop();
        }
        format!("{}.{}", whole, frac_string)
    }

    fn parse_solana_native_transfer(payload: &[u8]) -> Result<ParsedSolanaNativeTransfer, &'static str> {
        let mut pos = 0usize;
        Self::read_u8(payload, &mut pos)?;
        Self::read_u8(payload, &mut pos)?;
        Self::read_u8(payload, &mut pos)?;

        let account_count = Self::read_shortvec(payload, &mut pos)?;
        let mut accounts: Vec<String> = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            let bytes = Self::read_bytes(payload, &mut pos, 32)?;
            accounts.push(bs58::encode(bytes).into_string());
        }

        Self::read_bytes(payload, &mut pos, 32)?; // recent blockhash

        let instruction_count = Self::read_shortvec(payload, &mut pos)?;
        if instruction_count != 1 {
            return Err("expected exactly one instruction");
        }

        let program_id_index = Self::read_u8(payload, &mut pos)? as usize;
        let account_index_count = Self::read_shortvec(payload, &mut pos)?;
        if account_index_count != 2 {
            return Err("expected transfer account list");
        }
        let from_index = Self::read_u8(payload, &mut pos)? as usize;
        let destination_index = Self::read_u8(payload, &mut pos)? as usize;
        let data_len = Self::read_shortvec(payload, &mut pos)?;
        let data = Self::read_bytes(payload, &mut pos, data_len)?;

        if pos != payload.len() {
            return Err("unexpected trailing bytes");
        }
        if program_id_index >= accounts.len()
            || from_index >= accounts.len()
            || destination_index >= accounts.len()
        {
            return Err("account index out of range");
        }
        if accounts[program_id_index] != SOLANA_SYSTEM_PROGRAM_ID {
            return Err("not a system transfer");
        }
        if data.len() != 12 {
            return Err("unexpected instruction data len");
        }

        let instruction = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if instruction != 2 {
            return Err("not a transfer opcode");
        }
        let lamports = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);

        Ok(ParsedSolanaNativeTransfer {
            from_public_key: accounts[from_index].clone(),
            destination: accounts[destination_index].clone(),
            lamports,
        })
    }

    fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, &'static str> {
        if *pos >= data.len() {
            return Err("unexpected eof");
        }
        let value = data[*pos];
        *pos += 1;
        Ok(value)
    }

    fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], &'static str> {
        if data.len().saturating_sub(*pos) < len {
            return Err("unexpected eof");
        }
        let start = *pos;
        *pos += len;
        Ok(&data[start..start + len])
    }

    fn read_shortvec(data: &[u8], pos: &mut usize) -> Result<usize, &'static str> {
        let mut result = 0usize;
        let mut shift = 0usize;
        loop {
            let byte = Self::read_u8(data, pos)? as usize;
            result |= (byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift > 28 {
                return Err("shortvec overflow");
            }
        }
    }

    fn push_index(&mut self, account: &AccountId, pk: String) {
        let mut current = self.subkey_index.get(account).unwrap_or_default();
        if !current.contains(&pk) {
            current.push(pk);
            self.subkey_index.insert(account, &current);
        }
    }

    fn drop_from_index(&mut self, account: &AccountId, pk: &str) {
        if let Some(mut current) = self.subkey_index.get(account) {
            current.retain(|k| k != pk);
            self.subkey_index.insert(account, &current);
        }
    }

    fn log_event(event: &str, data: serde_json::Value) {
        let payload = serde_json::json!({
            "standard": "safu-subkey",
            "version": "0.1.0",
            "event": event,
            "data": data
        });
        env::log_str(&payload.to_string());
    }

    fn normalize_api_key_policy(policy: ApiKeyPolicyV1) -> ApiKeyPolicyV1 {
        let version = policy.version.trim().to_string();
        let template_id = policy.template_id.trim().to_string();
        let asset_type = policy.asset_type.trim().to_lowercase();
        let asset_id = policy
            .asset_id
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty());
        let allow_destinations: Vec<String> = policy
            .allow_destinations
            .into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect();

        require!(!version.is_empty(), "version required");
        require!(!template_id.is_empty(), "template_id required");
        require!(!asset_type.is_empty(), "asset_type required");
        if policy.max_per_period_native.is_some() || policy.max_tx_count_per_period.is_some() {
            require!(
                policy.period_seconds.unwrap_or(0) > 0,
                "period_seconds required"
            );
        }
        if let Some(max_per_tx_native) = policy.max_per_tx_native.as_ref() {
            require!(
                Self::parse_sol_amount_to_lamports(max_per_tx_native.trim()).is_some(),
                "invalid max_per_tx_native"
            );
        }
        if let Some(max_per_period_native) = policy.max_per_period_native.as_ref() {
            require!(
                Self::parse_sol_amount_to_lamports(max_per_period_native.trim()).is_some(),
                "invalid max_per_period_native"
            );
        }
        if let Some(spent) = policy.spent_this_period_native.as_ref() {
            require!(
                Self::parse_sol_amount_to_lamports(spent.trim()).is_some(),
                "invalid spent_this_period_native"
            );
        }

        ApiKeyPolicyV1 {
            version,
            template_id,
            asset_type,
            asset_id,
            max_per_tx_native: policy
                .max_per_tx_native
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty()),
            max_per_period_native: policy
                .max_per_period_native
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty()),
            period_seconds: policy.period_seconds.filter(|value| *value > 0),
            max_tx_count_per_period: policy.max_tx_count_per_period.filter(|value| *value > 0),
            allow_destinations,
            period_start_unix_seconds: policy.period_start_unix_seconds,
            spent_this_period_native: policy
                .spent_this_period_native
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty()),
            tx_count_this_period: policy.tx_count_this_period,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId};

    fn context(predecessor: AccountId, signer_pk: PublicKey) -> VMContextBuilder {
        let mut ctx = VMContextBuilder::new();
        ctx.predecessor_account_id(predecessor.clone());
        ctx.signer_account_id(predecessor);
        ctx.signer_account_pk(signer_pk);
        ctx
    }

    fn sample_paths() -> Vec<ChainPaths> {
        vec![ChainPaths {
            chain: Chain::Solana,
            paths: vec!["0".to_string(), "1".to_string()],
        }]
    }

    #[test]
    fn add_and_request_sign() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("alice.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.add_subkey(signer_pk.clone(), sample_paths());

        let req = SignRequest {
            chain: Chain::Solana,
            derivation_path: "0".to_string(),
            payload: Base64VecU8(vec![1, 2, 3]),
            memo: None,
        };

        // Should not panic (promise returned)
        let _ = contract.request_sign(req);
    }

    #[test]
    fn template_flow_happy_path() {
        let signer_pk: PublicKey = "ed25519:7a4Jhtp5mf7f5ez7sJ57zoCbsrSq8JhuWYeAMJtURHTh"
            .parse()
            .unwrap();
        let ctx = context("owner.testnet".parse().unwrap(), signer_pk.clone());
        testing_env!(ctx.build());
        let mut contract = Contract::new(
            "owner.testnet".parse().unwrap(),
            "v1.signer-prod.testnet".parse().unwrap(),
        );

        contract.set_template(TxTemplate {
            template_id: "solana-send".to_string(),
            chain: Chain::Solana,
            kind: TxKind::SolanaNative,
            allowed_tokens: None,
        });
        contract.set_token_cap(Chain::Solana, None, U128(1_000_000));

        contract.add_subkey(signer_pk.clone(), sample_paths());

        let request = TemplateSignRequest {
            template_id: "solana-send".to_string(),
            chain: Chain::Solana,
            derivation_path: "0".to_string(),
            to: "SomeSolanaAddress".to_string(),
            amount: U128(5),
            token_contract: None,
            symbol: None,
            evm_chain_id: None,
            memo: None,
        };

        let _ = contract.request_template_sign(request);
    }

    #[test]
    fn parse_sol_amount_to_lamports_works() {
        assert_eq!(Contract::parse_sol_amount_to_lamports("0.02"), Some(20_000_000));
        assert_eq!(Contract::parse_sol_amount_to_lamports("1"), Some(1_000_000_000));
        assert_eq!(Contract::parse_sol_amount_to_lamports("0.000000001"), Some(1));
        assert_eq!(Contract::parse_sol_amount_to_lamports(""), None);
        assert_eq!(Contract::parse_sol_amount_to_lamports("1.0000000001"), None);
    }
}
