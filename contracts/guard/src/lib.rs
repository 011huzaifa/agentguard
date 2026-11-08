use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{LookupMap, LookupSet, Vector};
use near_sdk::events::Nep297Event;
use near_sdk::{
    env, near, require, AccountId, Allowance, CryptoHash, Gas, NearSchema, NearToken, Promise, PublicKey,
};

const MAX_BUCKETS: u32 = 24;
const MAX_RECIPIENTS: usize = 100;
const MAX_TOKENS: usize = 10;
const MAX_AGENTS: u32 = 20;
const MAX_PENDING_IDS: usize = 100;
const DECISION_CAPACITY: u64 = 100;
const CALLBACK_GAS: Gas = Gas::from_tgas(20);
const MIN_BUCKET_NS: u64 = 1_000_000_000;
const MEMO_LIMIT: usize = 256;
const MAX_ALLOWANCE_YOCTO: u128 = 250_000_000_000_000_000_000_000; // 0.25 NEAR

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(BorshSerialize, BorshDeserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub enum RequestStatus {
    Pending,
    Executing,
    Executed,
    Failed,
    Rejected,
    Expired,
    Denied,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(BorshSerialize, BorshDeserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub enum UnknownRecipientPolicy {
    Deny,
    Escalate,
}

#[derive(Clone, Serialize, Deserialize)]
#[derive(BorshSerialize, BorshDeserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct TokenPolicy {
    pub token: Option<AccountId>,
    pub per_payment_cap: NearToken,
    pub window_budget: NearToken,
    pub approval_threshold: NearToken,
    pub review_required_above: NearToken,
}

#[derive(Clone, Serialize, Deserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct AgentPolicy {
    pub count_limit: u32,
    pub cooldown_ns: u64,
    pub window_ns: u64,
    pub bucket_count: u32,
    pub max_pending: u32,
    pub max_denials: u32,
    pub denial_window_ns: u64,
    pub expiry_ns: u64,
    pub recipients: Vec<AccountId>,
    pub tokens: Vec<TokenPolicy>,
    pub allowance: NearToken,
    pub unknown_recipient: UnknownRecipientPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct Verdict {
    pub request_id: u64,
    pub status: String,
    pub code: String,
    pub reason: String,
}

#[near(event_json(standard = "agentguard"))]
pub enum GuardEvent {
    #[event_version("1.0.0")]
    PaymentSubmitted { request_id: u64, agent: String, recipient: String, amount: String },
    #[event_version("1.0.0")]
    PaymentExecuted { request_id: u64 },
    #[event_version("1.0.0")]
    PaymentDenied { request_id: u64, code: String, reason: String },
    #[event_version("1.0.0")]
    PaymentApproved { request_id: u64 },
    #[event_version("1.0.0")]
    PaymentRejected { request_id: u64 },
    #[event_version("1.0.0")]
    ExpiredSweep { count: u64, request_ids: Vec<u64> },
    #[event_version("1.0.0")]
    ResolvedStuck { request_id: u64 },
    #[event_version("1.0.0")]
    PolicyUpdated { agent: String },
    #[event_version("1.0.0")]
    AgentAdded { agent: String },
    #[event_version("1.0.0")]
    AgentRemoved { agent: String },
    #[event_version("1.0.0")]
    Reauthorized { agent: String },
    #[event_version("1.0.0")]
    Unfrozen { agent: String },
    #[event_version("1.0.0")]
    Flagged {},
    #[event_version("1.0.0")]
    Cleared {},
    #[event_version("1.0.0")]
    Killed {},
    #[event_version("1.0.0")]
    Resumed {},
}

#[derive(Clone, Serialize, Deserialize)]
#[derive(BorshSerialize, BorshDeserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct Decision {
    pub request_id: u64,
    pub agent: String,
    pub recipient: AccountId,
    pub token: Option<AccountId>,
    pub amount: NearToken,
    pub approved: bool,
    pub reason: String,
    pub timestamp_ns: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[derive(BorshSerialize, BorshDeserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct PaymentRequest {
    pub id: u64,
    pub nonce: u64,
    pub agent: PublicKey,
    pub recipient: AccountId,
    pub token: Option<AccountId>,
    pub amount: NearToken,
    pub request_hash: CryptoHash,
    pub memo: Option<String>,
    pub created_ns: u64,
    pub expires_ns: u64,
    pub status: RequestStatus,
    pub bucket_index: u64,
    pub reserved: bool,
    pub window_ns: u64,
    pub bucket_count: u32,
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[derive(NearSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct AgentConfig {
    pub count_limit: u32,
    pub cooldown_ns: u64,
    pub expiry_ns: u64,
    pub window_ns: u64,
    pub bucket_count: u32,
    pub max_pending: u32,
    pub pending_count: u32,
    pub max_denials: u32,
    pub denial_count: u32,
    pub denial_window_start_ns: u64,
    pub denial_window_ns: u64,
    pub frozen: bool,
    pub allowance: NearToken,
    pub last_payment_ns: u64,
    pub window_start_ns: u64,
    pub count_in_window: u32,
    pub recipients: Vec<AccountId>,
    pub tokens: Vec<TokenPolicy>,
    pub pending_ids: Vec<u64>,
    pub unknown_recipient: UnknownRecipientPolicy,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SpendKey {
    pub agent: Vec<u8>,
    pub token: Option<AccountId>,
    pub window_ns: u64,
    pub bucket_count: u32,
    pub bucket: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct HashInput {
    pub agent: Vec<u8>,
    pub recipient: AccountId,
    pub token: Option<AccountId>,
    pub amount: NearToken,
    pub memo_hash: Vec<u8>,
    pub nonce: u64,
    pub request_id: u64,
}

#[near(contract_state)]
pub struct Contract {
    pub owners: LookupSet<PublicKey>,
    pub sentinels: LookupSet<PublicKey>,
    pub halted: bool,
    pub flagged: bool,
    pub killed: bool,
    pub agents: LookupMap<PublicKey, AgentConfig>,
    pub agent_keys: Vector<PublicKey>,
    pub requests: LookupMap<u64, PaymentRequest>,
    pub next_request_id: u64,
    pub next_nonce: u64,
    pub decisions: LookupMap<u64, Decision>,
    pub decision_head: u64,
    pub decision_capacity: u64,
    pub spent: LookupMap<SpendKey, NearToken>,
    pub in_flight_total: NearToken,
}

impl Default for Contract {
    fn default() -> Self {
        Self {
            owners: LookupSet::new(b"o"),
            sentinels: LookupSet::new(b"s"),
            halted: false,
            flagged: false,
            killed: false,
            agents: LookupMap::new(b"a"),
            agent_keys: Vector::new(b"k"),
            requests: LookupMap::new(b"q"),
            next_request_id: 1,
            next_nonce: 1,
            decisions: LookupMap::new(b"d"),
            decision_head: 0,
            decision_capacity: DECISION_CAPACITY,
            spent: LookupMap::new(b"x"),
            in_flight_total: NearToken::from_yoctonear(0),
        }
    }
}

#[near]
impl Contract {
    #[init]
    #[private]
    pub fn new(owner_pk: PublicKey) -> Self {
        let mut c = Self::default();
        c.owners.insert(owner_pk);
        c
    }

    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "predecessor must be contract account"
        );
        require!(
            self.owners.contains(&env::signer_account_pk()),
            "owner only"
        );
    }
    fn assert_owner_or_sentinel(&self) {
        let pk = env::signer_account_pk();
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "predecessor must be contract account"
        );
        require!(
            self.owners.contains(&pk) || self.sentinels.contains(&pk),
            "owner or sentinel only"
        );
    }
    fn assert_agent(&self) -> PublicKey {
        let pk = env::signer_account_pk();
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "predecessor must be contract account"
        );
        require!(self.agents.get(&pk).is_some(), "unknown agent");
        let cfg = self.agents.get(&pk).unwrap();
        require!(!cfg.frozen, "agent frozen");
        require!(!self.halted, "guard halted");
        pk
    }

    fn storage_reserve(&self) -> NearToken {
        let usage = env::storage_usage() as u128;
        let byte_cost = env::storage_byte_cost().as_yoctonear();
        NearToken::from_yoctonear(usage * byte_cost)
    }

    fn available_balance(&self) -> NearToken {
        let bal = env::account_balance();
        let reserve = self.storage_reserve();
        if bal <= reserve {
            NearToken::from_yoctonear(0)
        } else {
            NearToken::from_yoctonear(bal.as_yoctonear() - reserve.as_yoctonear())
        }
    }

    fn validate_policy(&self, policy: &AgentPolicy) {
        require!(policy.window_ns > 0, "window_ns must be > 0");
        require!(policy.bucket_count > 0 && policy.bucket_count <= MAX_BUCKETS, "invalid bucket_count");
        require!(policy.window_ns / policy.bucket_count as u64 >= MIN_BUCKET_NS, "bucket too short");
        require!(policy.recipients.len() <= MAX_RECIPIENTS, "too many recipients");
        require!(policy.tokens.len() <= MAX_TOKENS, "too many tokens");
        require!(policy.max_pending >= 1, "max_pending must be >= 1");
        require!(policy.max_pending <= MAX_PENDING_IDS as u32, "max_pending too high");
        require!(policy.max_denials >= 1, "max_denials must be >= 1");
        require!(policy.count_limit >= 1, "count_limit must be >= 1");
        require!(policy.denial_window_ns >= 1, "denial_window_ns must be >= 1");
        require!(policy.allowance.as_yoctonear() > 0, "allowance must be > 0");
        require!(policy.allowance.as_yoctonear() <= MAX_ALLOWANCE_YOCTO, "allowance too high");
        for tp in &policy.tokens {
            require!(tp.token.is_none(), "non-native tokens not supported yet");
            require!(tp.per_payment_cap <= tp.window_budget, "cap > window budget");
            require!(tp.approval_threshold <= tp.window_budget, "threshold > window budget");
            require!(tp.review_required_above <= tp.window_budget, "review > window budget");
        }
    }

    fn compute_hash(
        &self,
        agent: &PublicKey,
        recipient: &AccountId,
        token: &Option<AccountId>,
        amount: NearToken,
        memo: &Option<String>,
        nonce: u64,
        request_id: u64,
    ) -> CryptoHash {
        let memo_hash = if let Some(m) = memo {
            env::sha256(m.as_bytes())
        } else {
            vec![0u8; 32]
        };
        let input = HashInput {
            agent: agent.as_bytes().to_vec(),
            recipient: recipient.clone(),
            token: token.clone(),
            amount,
            memo_hash,
            nonce,
            request_id,
        };
        let bytes = near_sdk::borsh::to_vec(&input).unwrap();
        env::sha256(&bytes).try_into().unwrap()
    }

    fn bucket_duration(window_ns: u64, bucket_count: u32) -> u64 {
        window_ns / bucket_count as u64
    }

    fn window_spent(&self, agent_pk: &PublicKey, token: &Option<AccountId>, window_ns: u64, bucket_count: u32, now_bucket: u64) -> NearToken {
        let mut total: u128 = 0;
        let first = if now_bucket + 1 >= bucket_count as u64 {
            now_bucket + 1 - bucket_count as u64
        } else {
            0
        };
        for b in first..=now_bucket {
            let key = SpendKey {
                agent: agent_pk.as_bytes().to_vec(),
                token: token.clone(),
                window_ns,
                bucket_count,
                bucket: b,
            };
            if let Some(v) = self.spent.get(&key) {
                total += v.as_yoctonear();
            }
        }
        NearToken::from_yoctonear(total)
    }

    fn record_decision(&mut self, d: Decision) {
        let slot = self.decision_head % self.decision_capacity;
        self.decisions.insert(slot, d);
        self.decision_head += 1;
    }

    fn sweep_expired(&mut self, agent_pk: &PublicKey, now: u64) {
        // collect
        let pending_ids = self.agents.get(agent_pk).map(|c| c.pending_ids.clone()).unwrap_or_default();
        let mut expired_ids = Vec::new();
        let mut expired_infos = Vec::new();
        let mut keep = Vec::new();
        for id in pending_ids {
            let info = self.requests.get(&id).cloned();
            let expired = info.as_ref().map(|r| r.status == RequestStatus::Pending && now > r.expires_ns).unwrap_or(false);
            if expired {
                expired_ids.push(id);
                if let Some(r) = info { expired_infos.push((id, r)); }
            } else {
                keep.push(id);
            }
        }
        for id in &expired_ids {
            if let Some(r) = self.requests.get_mut(id) {
                r.status = RequestStatus::Expired;
            }
        }
        if let Some(cfg) = self.agents.get_mut(agent_pk) {
            cfg.pending_count = cfg.pending_count.saturating_sub(expired_ids.len() as u32);
            cfg.pending_ids = keep;
        }
        if !expired_ids.is_empty() {
            let mut ids = expired_ids.clone();
            if ids.len() > 100 { ids.truncate(100); }
            GuardEvent::ExpiredSweep { count: expired_ids.len() as u64, request_ids: ids }.emit();
        }
    }

    fn deny(
        &mut self,
        agent_pk: PublicKey,
        recipient: AccountId,
        token: Option<AccountId>,
        amount: NearToken,
        code: String,
        reason: String,
        now: u64,
    ) -> Verdict {
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        if let Some(cfg) = self.agents.get_mut(&agent_pk) {
            if cfg.denial_window_start_ns == 0 || now >= cfg.denial_window_start_ns + cfg.denial_window_ns {
                cfg.denial_window_start_ns = now;
                cfg.denial_count = 0;
            }
            cfg.denial_count += 1;
            if cfg.denial_count >= cfg.max_denials {
                cfg.frozen = true;
            }
        }
        GuardEvent::PaymentDenied { request_id, code: code.clone(), reason: reason.clone() }.emit();
        self.record_decision(Decision {
            request_id,
            agent: agent_pk.to_string(),
            recipient,
            token,
            amount,
            approved: false,
            reason: reason.clone(),
            timestamp_ns: now,
        });
        Verdict {
            request_id,
            status: "denied".to_string(),
            code,
            reason,
        }
    }

    pub fn add_sentinel(&mut self, pk: PublicKey) -> Promise {
        self.assert_owner();
        self.sentinels.insert(pk.clone());
        Promise::new(env::current_account_id()).add_access_key_allowance(
            pk,
            Allowance::limited(NearToken::from_millinear(10)).unwrap(),
            env::current_account_id(),
            "flag",
        )
    }

    pub fn add_agent(&mut self, agent_pk: PublicKey, policy: AgentPolicy) -> Promise {
        self.assert_owner();
        require!(self.agent_keys.len() < MAX_AGENTS, "too many agents");
        require!(!self.agents.contains_key(&agent_pk), "agent exists");
        self.validate_policy(&policy);

        let cfg = AgentConfig {
            count_limit: policy.count_limit,
            cooldown_ns: policy.cooldown_ns,
            expiry_ns: policy.expiry_ns,
            window_ns: policy.window_ns,
            bucket_count: policy.bucket_count,
            max_pending: policy.max_pending,
            pending_count: 0,
            max_denials: policy.max_denials,
            denial_count: 0,
            denial_window_start_ns: 0,
            denial_window_ns: policy.denial_window_ns,
            frozen: false,
            allowance: policy.allowance,
            last_payment_ns: 0,
            window_start_ns: 0,
            count_in_window: 0,
            recipients: policy.recipients,
            tokens: policy.tokens,
            pending_ids: Vec::new(),
            unknown_recipient: policy.unknown_recipient,
        };
        self.agents.insert(agent_pk.clone(), cfg);
        self.agent_keys.push(agent_pk.clone());

        GuardEvent::AgentAdded { agent: agent_pk.to_string() }.emit();
        Promise::new(env::current_account_id()).add_access_key_allowance(
            agent_pk,
            Allowance::limited(policy.allowance).unwrap(),
            env::current_account_id(),
            "request_payment",
        )
    }

    pub fn remove_agent(&mut self, agent_pk: PublicKey) -> Promise {
        self.assert_owner();
        require!(self.agents.get(&agent_pk).is_some(), "unknown agent");
        self.agents.remove(&agent_pk);
        let mut i = 0;
        while i < self.agent_keys.len() {
            if self.agent_keys.get(i).unwrap() == &agent_pk {
                self.agent_keys.swap_remove(i);
                break;
            }
            i += 1;
        }
        GuardEvent::AgentRemoved { agent: agent_pk.to_string() }.emit();
        Promise::new(env::current_account_id()).delete_key(agent_pk)
    }

    pub fn reauthorize(&mut self, agent_pk: PublicKey) -> Promise {
        self.assert_owner();
        let cfg = self.agents.get(&agent_pk).expect("unknown agent");
        let allowance = cfg.allowance;
        GuardEvent::Reauthorized { agent: agent_pk.to_string() }.emit();
        Promise::new(env::current_account_id()).add_access_key_allowance(
            agent_pk,
            Allowance::limited(allowance).unwrap(),
            env::current_account_id(),
            "request_payment",
        )
    }

    pub fn unfreeze_agent(&mut self, agent_pk: PublicKey) {
        self.assert_owner();
        let cfg = self.agents.get_mut(&agent_pk).expect("unknown agent");
        cfg.frozen = false;
        cfg.denial_count = 0;
        cfg.denial_window_start_ns = 0;
        GuardEvent::Unfrozen { agent: agent_pk.to_string() }.emit();
    }

    pub fn update_policy(&mut self, agent_pk: PublicKey, policy: AgentPolicy) {
        self.assert_owner();
        self.validate_policy(&policy);
        let cfg = self.agents.get_mut(&agent_pk).expect("unknown agent");
        // reset window counters if window changed
        if cfg.window_ns != policy.window_ns || cfg.bucket_count != policy.bucket_count {
            cfg.window_start_ns = 0;
            cfg.count_in_window = 0;
        }
        cfg.count_limit = policy.count_limit;
        cfg.cooldown_ns = policy.cooldown_ns;
        cfg.expiry_ns = policy.expiry_ns;
        cfg.window_ns = policy.window_ns;
        cfg.bucket_count = policy.bucket_count;
        cfg.max_pending = policy.max_pending;
        cfg.max_denials = policy.max_denials;
        cfg.denial_window_ns = policy.denial_window_ns;
        cfg.allowance = policy.allowance;
        cfg.recipients = policy.recipients;
        cfg.tokens = policy.tokens;
        cfg.unknown_recipient = policy.unknown_recipient;
        GuardEvent::PolicyUpdated { agent: agent_pk.to_string() }.emit();
    }

    pub fn flag(&mut self) {
        self.assert_owner_or_sentinel();
        self.flagged = true;
        self.halted = true;
        GuardEvent::Flagged {}.emit();
    }

    pub fn clear(&mut self) {
        self.assert_owner();
        self.flagged = false;
        self.halted = self.killed;
        GuardEvent::Cleared {}.emit();
    }

    pub fn kill(&mut self) -> Promise {
        self.assert_owner();
        self.killed = true;
        self.halted = true;
        self.flagged = false;
        GuardEvent::Killed {}.emit();
        // one detached promise per key
        let mut i = 0;
        while i < self.agent_keys.len() {
            let pk = self.agent_keys.get(i).unwrap().clone();
            Promise::new(env::current_account_id()).delete_key(pk).detach();
            i += 1;
        }
        Promise::new(env::current_account_id())
    }

    pub fn resume(&mut self) -> Promise {
        self.assert_owner();
        self.killed = false;
        self.halted = self.flagged;
        GuardEvent::Resumed {}.emit();
        let mut i = 0;
        while i < self.agent_keys.len() {
            let pk = self.agent_keys.get(i).unwrap().clone();
            let allowance = self.agents.get(&pk).map(|c| c.allowance).unwrap_or(NearToken::from_millinear(10));
            Promise::new(env::current_account_id())
                .add_access_key_allowance(
                    pk,
                    Allowance::limited(allowance).unwrap(),
                    env::current_account_id(),
                    "request_payment",
                )
                .detach();
            i += 1;
        }
        Promise::new(env::current_account_id())
    }

    pub fn resolve_stuck(&mut self, request_id: u64) {
        self.assert_owner();
        let req = self.requests.get(&request_id).expect("unknown request").clone();
        require!(req.status == RequestStatus::Executing, "not stuck");
        if req.reserved {
            let agent_pk = req.agent.clone();
            let bucket_index = req.bucket_index;
            let amount = req.amount;
            let token = req.token.clone();
            let window_ns = req.window_ns;
            let bucket_count = req.bucket_count;
            let key = SpendKey {
                agent: agent_pk.as_bytes().to_vec(),
                token: token.clone(),
                window_ns,
                bucket_count,
                bucket: bucket_index,
            };
            if let Some(v) = self.spent.get(&key).copied() {
                let newv = v.as_yoctonear().saturating_sub(amount.as_yoctonear());
                self.spent.insert(key, NearToken::from_yoctonear(newv));
            }
            self.in_flight_total = NearToken::from_yoctonear(self.in_flight_total.as_yoctonear().saturating_sub(amount.as_yoctonear()));
            if let Some(cfg) = self.agents.get_mut(&agent_pk) {
                cfg.count_in_window = cfg.count_in_window.saturating_sub(1);
            }
        }
        if let Some(r) = self.requests.get_mut(&request_id) {
            r.status = RequestStatus::Failed;
            r.reserved = false;
        }
        GuardEvent::ResolvedStuck { request_id }.emit();
        self.record_decision(Decision {
            request_id,
            agent: req.agent.to_string(),
            recipient: req.recipient.clone(),
            token: req.token.clone(),
            amount: req.amount,
            approved: false,
            reason: "resolved stuck".to_string(),
            timestamp_ns: env::block_timestamp(),
        });
    }

    pub fn request_payment(
        &mut self,
        recipient: AccountId,
        token: Option<AccountId>,
        amount: NearToken,
        memo: Option<String>,
    ) -> Verdict {
        // gas check
        require!(env::prepaid_gas() >= Gas::from_tgas(50), "insufficient prepaid gas");

        let agent_pk = self.assert_agent();
        let now = env::block_timestamp();

        // sweep expired
        self.sweep_expired(&agent_pk, now);

        let memo = if let Some(m) = memo {
            if m.len() > MEMO_LIMIT {
                return self.deny(agent_pk, recipient, token, amount, "memo_too_long".to_string(), "memo exceeds limit".to_string(), now);
            }
            Some(m)
        } else {
            None
        };

        if amount <= NearToken::from_yoctonear(0) {
            return self.deny(agent_pk, recipient, token, amount, "invalid_amount".to_string(), "amount must be > 0".to_string(), now);
        }

        let cfg = match self.agents.get(&agent_pk) {
            Some(c) => c.clone(),
            None => return self.deny(agent_pk, recipient, token, amount, "unknown_agent".to_string(), "unknown agent".to_string(), now),
        };

        let recipient_allowed = cfg.recipients.iter().any(|r| r == &recipient);
        let needs_approval = if !recipient_allowed {
            match cfg.unknown_recipient {
                UnknownRecipientPolicy::Deny => {
                    return self.deny(agent_pk, recipient, token, amount, "unknown_recipient".to_string(), "recipient not allowed".to_string(), now);
                }
                UnknownRecipientPolicy::Escalate => true,
            }
        } else {
            false
        };

        let tp = match cfg.tokens.iter().find(|t| t.token == token) {
            Some(t) => t.clone(),
            None => return self.deny(agent_pk, recipient, token, amount, "token_not_allowed".to_string(), "token not allowed".to_string(), now),
        };

        if token.is_some() {
            return self.deny(agent_pk, recipient, token, amount, "token_not_supported".to_string(), "non-native tokens not supported yet".to_string(), now);
        }

        if amount > tp.per_payment_cap {
            return self.deny(agent_pk, recipient, token, amount, "per_payment_cap".to_string(), "exceeds per-payment cap".to_string(), now);
        }

        let approval_needed = needs_approval || amount > tp.approval_threshold || amount > tp.review_required_above;

        if cfg.last_payment_ns > 0 && now < cfg.last_payment_ns + cfg.cooldown_ns {
            return self.deny(agent_pk, recipient, token, amount, "cooldown".to_string(), "cooldown active".to_string(), now);
        }

        let bd = Self::bucket_duration(cfg.window_ns, cfg.bucket_count);
        let now_bucket = now / bd;
        let spent = self.window_spent(&agent_pk, &token, cfg.window_ns, cfg.bucket_count, now_bucket);
        if spent.as_yoctonear() + amount.as_yoctonear() > tp.window_budget.as_yoctonear() {
            return self.deny(agent_pk, recipient, token, amount, "window_budget".to_string(), "window budget exceeded".to_string(), now);
        }

        let available = self.available_balance();
        if amount.as_yoctonear() + self.in_flight_total.as_yoctonear() > available.as_yoctonear() {
            return self.deny(agent_pk, recipient, token, amount, "insufficient_balance".to_string(), "insufficient balance".to_string(), now);
        }

        let mut cfg_mut = self.agents.get_mut(&agent_pk).unwrap();
        if cfg_mut.window_start_ns == 0 || now >= cfg_mut.window_start_ns + cfg_mut.window_ns {
            cfg_mut.window_start_ns = now;
            cfg_mut.count_in_window = 0;
        }
        if cfg_mut.count_in_window >= cfg_mut.count_limit {
            return self.deny(agent_pk, recipient, token, amount, "count_limit".to_string(), "count limit exceeded".to_string(), now);
        }

        if approval_needed && cfg_mut.pending_count >= cfg_mut.max_pending {
            return self.deny(agent_pk, recipient, token, amount, "max_pending".to_string(), "max pending exceeded".to_string(), now);
        }

        let request_id = self.next_request_id;
        self.next_request_id += 1;
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        let request_hash = self.compute_hash(&agent_pk, &recipient, &token, amount, &memo, nonce, request_id);

        if approval_needed {
            let mut cfg_mut = self.agents.get_mut(&agent_pk).unwrap();
            cfg_mut.pending_count += 1;
            if cfg_mut.pending_ids.len() < MAX_PENDING_IDS {
                cfg_mut.pending_ids.push(request_id);
            }
            let req = PaymentRequest {
                id: request_id,
                nonce,
                agent: agent_pk.clone(),
                recipient: recipient.clone(),
                token: token.clone(),
                amount,
                request_hash,
                memo: memo.clone(),
                created_ns: now,
                expires_ns: now + cfg.expiry_ns,
                status: RequestStatus::Pending,
                bucket_index: 0,
                reserved: false,
                window_ns: cfg.window_ns,
                bucket_count: cfg.bucket_count,
            };
            self.requests.insert(request_id, req);
            GuardEvent::PaymentSubmitted { request_id, agent: agent_pk.to_string(), recipient: recipient.to_string(), amount: amount.to_string() }.emit();
            self.record_decision(Decision {
                request_id,
                agent: agent_pk.to_string(),
                recipient: recipient.clone(),
                token: token.clone(),
                amount,
                approved: false,
                reason: "pending approval".to_string(),
                timestamp_ns: now,
            });
            return Verdict {
                request_id,
                status: "pending".to_string(),
                code: "pending_approval".to_string(),
                reason: "awaiting owner approval".to_string(),
            };
        }

        // execute immediately
        let bucket_index = now_bucket;
        let cfg_mut = self.agents.get_mut(&agent_pk).unwrap();
        let key = SpendKey {
            agent: agent_pk.as_bytes().to_vec(),
            token: token.clone(),
            window_ns: cfg.window_ns,
            bucket_count: cfg.bucket_count,
            bucket: bucket_index,
        };
        let spent_now = self.spent.get(&key).copied().unwrap_or(NearToken::from_yoctonear(0));
        self.spent.insert(key, NearToken::from_yoctonear(spent_now.as_yoctonear() + amount.as_yoctonear()));
        cfg_mut.count_in_window += 1;
        cfg_mut.last_payment_ns = now;

        self.in_flight_total = NearToken::from_yoctonear(self.in_flight_total.as_yoctonear() + amount.as_yoctonear());

        let req = PaymentRequest {
            id: request_id,
            nonce,
            agent: agent_pk.clone(),
            recipient: recipient.clone(),
            token: token.clone(),
            amount,
            request_hash,
            memo: memo.clone(),
            created_ns: now,
            expires_ns: now + cfg.expiry_ns,
            status: RequestStatus::Executing,
            bucket_index,
            reserved: true,
            window_ns: cfg.window_ns,
            bucket_count: cfg.bucket_count,
        };
        self.requests.insert(request_id, req);

        if token.is_none() {
            Promise::new(recipient.clone())
                .transfer(amount)
                .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_transfer_result(request_id))
                .detach();
        }

        GuardEvent::PaymentSubmitted { request_id, agent: agent_pk.to_string(), recipient: recipient.to_string(), amount: amount.to_string() }.emit();
        self.record_decision(Decision {
            request_id,
            agent: agent_pk.to_string(),
            recipient: recipient.clone(),
            token: token.clone(),
            amount,
            approved: true,
            reason: "submitted".to_string(),
            timestamp_ns: now,
        });

        Verdict {
            request_id,
            status: "executing".to_string(),
            code: "ok".to_string(),
            reason: "submitted".to_string(),
        }
    }

    #[private]
    pub fn on_transfer_result(&mut self, request_id: u64) {
        let req = self.requests.get(&request_id).expect("unknown request").clone();
        require!(req.status == RequestStatus::Executing, "not executing");
        let success = match env::promise_result(0) {
            near_sdk::PromiseResult::Successful(_) => true,
            _ => false,
        };
        if success {
            if let Some(r) = self.requests.get_mut(&request_id) {
                r.status = RequestStatus::Executed;
                r.reserved = false;
            }
            self.in_flight_total = NearToken::from_yoctonear(self.in_flight_total.as_yoctonear().saturating_sub(req.amount.as_yoctonear()));
            GuardEvent::PaymentExecuted { request_id }.emit();
            self.record_decision(Decision {
                request_id,
                agent: req.agent.to_string(),
                recipient: req.recipient.clone(),
                token: req.token.clone(),
                amount: req.amount,
                approved: true,
                reason: "transfer succeeded".to_string(),
                timestamp_ns: env::block_timestamp(),
            });
        } else {
            if req.reserved {
                let agent_pk = req.agent.clone();
                let bucket_index = req.bucket_index;
                let amount = req.amount;
                let token = req.token.clone();
                let window_ns = req.window_ns;
                let bucket_count = req.bucket_count;
                let key = SpendKey {
                    agent: agent_pk.as_bytes().to_vec(),
                    token: token.clone(),
                    window_ns,
                    bucket_count,
                    bucket: bucket_index,
                };
                if let Some(v) = self.spent.get(&key).copied() {
                    let newv = v.as_yoctonear().saturating_sub(amount.as_yoctonear());
                    self.spent.insert(key, NearToken::from_yoctonear(newv));
                }
                self.in_flight_total = NearToken::from_yoctonear(self.in_flight_total.as_yoctonear().saturating_sub(amount.as_yoctonear()));
                if let Some(cfg) = self.agents.get_mut(&agent_pk) {
                    cfg.count_in_window = cfg.count_in_window.saturating_sub(1);
                }
            }
            if let Some(r) = self.requests.get_mut(&request_id) {
                r.status = RequestStatus::Failed;
                r.reserved = false;
            }
            GuardEvent::PaymentDenied { request_id, code: "transfer_failed".to_string(), reason: "transfer failed".to_string() }.emit();
            self.record_decision(Decision {
                request_id,
                agent: req.agent.to_string(),
                recipient: req.recipient.clone(),
                token: req.token.clone(),
                amount: req.amount,
                approved: false,
                reason: "transfer failed".to_string(),
                timestamp_ns: env::block_timestamp(),
            });
        }
    }

    pub fn approve(&mut self, request_id: u64, request_hash: CryptoHash) -> u64 {
        require!(env::prepaid_gas() >= Gas::from_tgas(50), "insufficient prepaid gas");
        self.assert_owner();
        require!(!self.halted, "guard halted");
        let req = self.requests.get(&request_id).expect("unknown request").clone();
        require!(req.status == RequestStatus::Pending, "not pending");
        require!(env::block_timestamp() <= req.expires_ns, "expired");
        require!(req.request_hash == request_hash, "hash mismatch");

        let agent_pk = req.agent.clone();
        let recipient = req.recipient.clone();
        let token = req.token.clone();
        let amount = req.amount;
        let cfg = self.agents.get(&agent_pk).expect("agent removed").clone();
        let now = env::block_timestamp();
        let bd = Self::bucket_duration(cfg.window_ns, cfg.bucket_count);
        let now_bucket = now / bd;
        let spent = self.window_spent(&agent_pk, &token, cfg.window_ns, cfg.bucket_count, now_bucket);
        let tp = cfg.tokens.iter().find(|t| t.token == token).expect("token policy missing");
        require!(spent.as_yoctonear() + amount.as_yoctonear() <= tp.window_budget.as_yoctonear(), "window budget exceeded");

        // storage reserve
        let available = self.available_balance();
        require!(amount.as_yoctonear() + self.in_flight_total.as_yoctonear() <= available.as_yoctonear(), "insufficient balance");

        let cfg_mut = self.agents.get_mut(&agent_pk).unwrap();
        if cfg_mut.window_start_ns == 0 || now >= cfg_mut.window_start_ns + cfg_mut.window_ns {
            cfg_mut.window_start_ns = now;
            cfg_mut.count_in_window = 0;
        }
        require!(cfg_mut.count_in_window < cfg_mut.count_limit, "count limit exceeded");

        let bucket_index = now_bucket;
        let key = SpendKey {
            agent: agent_pk.as_bytes().to_vec(),
            token: token.clone(),
            window_ns: cfg.window_ns,
            bucket_count: cfg.bucket_count,
            bucket: bucket_index,
        };
        let spent_now = self.spent.get(&key).copied().unwrap_or(NearToken::from_yoctonear(0));
        self.spent.insert(key, NearToken::from_yoctonear(spent_now.as_yoctonear() + amount.as_yoctonear()));
        cfg_mut.count_in_window += 1;
        cfg_mut.last_payment_ns = now;
        cfg_mut.pending_count = cfg_mut.pending_count.saturating_sub(1);
        // prune pending_ids
        cfg_mut.pending_ids.retain(|id| *id != request_id);

        self.in_flight_total = NearToken::from_yoctonear(self.in_flight_total.as_yoctonear() + amount.as_yoctonear());

        let r = self.requests.get_mut(&request_id).unwrap();
        r.status = RequestStatus::Executing;
        r.bucket_index = bucket_index;
        r.reserved = true;
        r.window_ns = cfg.window_ns;
        r.bucket_count = cfg.bucket_count;

        if token.is_none() {
            Promise::new(recipient.clone())
                .transfer(amount)
                .then(Self::ext(env::current_account_id()).with_static_gas(CALLBACK_GAS).on_transfer_result(request_id))
                .detach();
        }

        GuardEvent::PaymentApproved { request_id }.emit();
        self.record_decision(Decision {
            request_id,
            agent: agent_pk.to_string(),
            recipient,
            token,
            amount,
            approved: true,
            reason: "approved".to_string(),
            timestamp_ns: now,
        });

        request_id
    }

    pub fn reject(&mut self, request_id: u64) {
        self.assert_owner();
        let (agent, recipient, token, amount, status) = {
            let r = self.requests.get(&request_id).expect("unknown request");
            require!(r.status == RequestStatus::Pending || r.status == RequestStatus::Expired, "not rejectable");
            (r.agent.clone(), r.recipient.clone(), r.token.clone(), r.amount, r.status)
        };
        let r = self.requests.get_mut(&request_id).unwrap();
        r.status = RequestStatus::Rejected;
        if let Some(cfg) = self.agents.get_mut(&agent) {
            if status == RequestStatus::Pending {
                cfg.pending_count = cfg.pending_count.saturating_sub(1);
            }
            cfg.pending_ids.retain(|id| *id != request_id);
        }
        GuardEvent::PaymentRejected { request_id }.emit();
        self.record_decision(Decision {
            request_id,
            agent: agent.to_string(),
            recipient,
            token,
            amount,
            approved: false,
            reason: "rejected".to_string(),
            timestamp_ns: env::block_timestamp(),
        });
    }

    pub fn pending_requests(&self, agent_pk: Option<PublicKey>) -> Vec<PaymentRequest> {
        let mut out = Vec::new();
        let ids: Vec<u64> = if let Some(pk) = &agent_pk {
            self.agents.get(pk).map(|c| c.pending_ids.clone()).unwrap_or_default()
        } else {
            let mut all = Vec::new();
            for pk in self.agent_keys.iter() {
                if let Some(c) = self.agents.get(pk) {
                    all.extend(c.pending_ids.clone());
                }
            }
            all
        };
        for id in ids {
            if let Some(r) = self.requests.get(&id) {
                if r.status == RequestStatus::Pending {
                    out.push(r.clone());
                }
            }
        }
        // prune terminal ids by rebuilding? view cannot mutate. Contract state not mutated in view.
        out
    }

    pub fn get_request(&self, request_id: u64) -> Option<PaymentRequest> {
        self.requests.get(&request_id).cloned()
    }

    pub fn get_policy(&self, agent_pk: PublicKey) -> Option<AgentConfig> {
        self.agents.get(&agent_pk).cloned()
    }

    pub fn recent_decisions(&self, limit: u64) -> Vec<Decision> {
        let mut out = Vec::new();
        if self.decision_head == 0 {
            return out;
        }
        let cap = self.decision_capacity;
        let mut i = 0;
        while i < limit && i < self.decision_head {
            let idx = (self.decision_head - 1 - i) % cap;
            if let Some(d) = self.decisions.get(&idx) {
                out.push(d.clone());
            }
            i += 1;
        }
        out
    }

    pub fn is_halted(&self) -> bool {
        self.halted
    }

    pub fn get_in_flight_total(&self) -> NearToken {
        self.in_flight_total
    }
}
