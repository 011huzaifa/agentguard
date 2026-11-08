# AgentGuard Specification

## Scope
Security protocol for AI agent payments on NEAR. Native NEAR path first; NEP-141 after.

## Accounts
- Guard contract lives on a dedicated sub-account holding only the agent budget.
- Owner controls it with a full-access key to that sub-account.
- Agent uses a function-call access key restricted to `request_payment` (explicit allowance).
- Contract identifies callers by `env::signer_account_pk()` (NEAR access keys share account id).

## Auth
- Privileged methods require `predecessor == current_account` AND signer pk in owner/sentinel set.
- Agent methods require `predecessor == current_account`, signer pk registered, not halted.
- Sentinel role: flag/clear kill switch only; cannot expand policy or add agents.

## Policy
Per agent:
- count_limit, cooldown_ns, window_ns, bucket_count, expiry_ns, recipients (allowlist)
- tokens: map token -> TokenPolicy

TokenPolicy:
- token: Option<AccountId> (None = native NEAR)
- per_payment_cap
- window_budget
- approval_threshold
- review_required_above

## Fixed-bucket budgets
- window_ns divided into bucket_count buckets.
- Each payment reserves amount in its bucket; sum of last bucket_count buckets <= window_budget.
- count_limit and cooldown are per agent.

## Request hash
request_hash = sha256(borsh(HashInput {
  agent: agent_pk bytes,
  recipient,
  token,
  amount,
  nonce,
  request_id
})).

## Nonce
- Global `next_nonce`, incremented per request.
- Stored in PaymentRequest.

## Flows
1. Agent `request_payment(recipient, token, amount, memo)`:
   - validates policy; if amount needs approval creates Pending request.
   - else reserves and executes transfer, callback reverts/releases on failure.
2. Owner `approve(request_id, request_hash)`:
   - verifies pending, not expired, hash match; reserves and executes.
3. Owner `reject(request_id)`.
4. Owner `update_policy(...)`, `remove_agent(...)`.
5. Owner `add_agent(pk, ...)` stores policy and issues AddKey restricted to request_payment.
6. `flag()` / `clear()` (owner or sentinel) sets halted.
7. `kill()` sets halted and deletes all agent keys.
8. `resume()` clears halted (owner re-adds keys if needed).

## Invariants
1. Agent key can move funds only via request_payment, only if policy allows.
2. Policy edits, approvals, key management, kill switch are owner-only.
3. Deny by default: unknown recipient/token denied.
4. Spending windows use block time; agent cannot reset counters.
5. Approvals bind to exact request hash.
6. Pending requests expire.
7. Kill switch halts all agent keys.
8. Update counters before transfer; revert in callback if transfer fails.
9. Every decision emits NEP-297 event.
10. Privileged methods check predecessor == current account and signer pk.
11. Reservation: reserve at payment start; release idempotently in callback on failure.
12. Storage reserve: never spend below storage-staking reserve.

## Reservation
- In-flight PaymentRequest stores bucket_index and reserved flag.
- Callback `#[private] on_transfer_result(request_id)` checks promise result.
- On failure, releases reserved amount/count idempotently.

## Events
- NEP-297 `EVENT_JSON:` with standard `agentguard`, version `1.0.0`.
- Bounded ring buffer: `LookupMap<u64, Decision>` + head counter (capacity 100).
- View `recent_decisions(limit)`.

## Storage reserve
- available = account_balance - (storage_usage * storage_byte_cost).
- Payments must not reduce below reserve.

## References
- Access keys: https://docs.near.org/protocol/accounts-contracts/access-keys
- Environment: https://docs.near.org/smart-contracts/anatomy/environment
- Actions: https://docs.near.org/smart-contracts/anatomy/actions
- near-sdk Promise: https://docs.rs/near-sdk/latest/near_sdk/struct.Promise.html
- near-workspaces: https://github.com/near/near-workspaces-rs
- Integration tests: https://docs.near.org/smart-contracts/testing/integration-test
- NEP-141: https://github.com/near/NEPs/blob/master/neps/nep-0141.md
- NEP-297: https://github.com/near/NEPs/blob/master/neps/nep-0297.md

## Known Limits
- Window change forgets history: changing window_ns/bucket_count resets count/window tracking; spend buckets are keyed by the new window/bucket dimensions.
- Storage growth: spend buckets are not garbage-collected; old buckets remain in storage.
- resolve_stuck caveat: owner can force-fail an Executing request and release its reservation; misuse can double-handle.

## Verdict codes/statuses
Statuses: pending, executing, executed, failed, rejected, expired, denied.
Codes: ok, pending_approval, unknown_recipient, recipient_not_allowed, token_not_allowed, token_not_supported, per_payment_cap, cooldown, window_budget, insufficient_balance, count_limit, max_pending, invalid_amount, memo_too_long, transfer_failed.
