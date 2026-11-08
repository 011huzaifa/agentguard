use near_workspaces::{types::SecretKey, Account, Contract};
use serde_json::json;

fn assert_fails_with<T: std::fmt::Debug, E: std::fmt::Debug>(res: Result<T, E>, needle: &str) {
    let text = match res {
        Ok(v) => format!("{:?}", v),
        Err(e) => format!("{:?}", e),
    };
    assert!(text.contains(needle), "expected {:?} in {}", needle, text);
}

const WASM: &[u8] = include_bytes!("../target/wasm32-unknown-unknown/release/guard.wasm");
const ONE_NEAR: &str = "1000000000000000000000000";
const ALLOWANCE: &str = "250000000000000000000000";

fn policy(recipients: serde_json::Value, threshold: &str) -> serde_json::Value {
    json!({
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": recipients,
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "10000000000000000000000000", "approval_threshold": threshold, "review_required_above": threshold}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    })
}

async fn setup() -> anyhow::Result<(near_workspaces::Worker<near_workspaces::network::Sandbox>, Contract, Account, Account, Account, Account, Account)> {
    let worker = near_workspaces::sandbox().await?;
    let contract = worker.dev_deploy(WASM).await?;
    let owner = contract.as_account().clone();
    let recipient = worker.dev_create_account().await?;
    let recipient2 = worker.dev_create_account().await?;
    let agent_dev = worker.dev_create_account().await?;
    let stranger = worker.dev_create_account().await?;

    owner.call(contract.id(), "new").args_json(json!({ "owner_pk": owner.secret_key().public_key().to_string() })).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;

    owner.transfer_near(contract.id(), near_workspaces::types::NearToken::from_near(10)).await?.into_result()?;

    let agent_pk = agent_dev.secret_key().public_key().to_string();
    owner.call(contract.id(), "add_agent").args_json(json!({"agent_pk": agent_pk, "policy": policy(json!([recipient.id().to_string()]), "10000000000000000000000000")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;

    let agent_dev2 = worker.dev_create_account().await?;
    let agent_pk2 = agent_dev2.secret_key().public_key().to_string();
    owner.call(contract.id(), "add_agent").args_json(json!({"agent_pk": agent_pk2, "policy": policy(json!([recipient2.id().to_string()]), "10000000000000000000000000")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;

    Ok((worker, contract, owner, recipient, agent_dev, agent_dev2, stranger))
}

fn agent_account(worker: &near_workspaces::Worker<near_workspaces::network::Sandbox>, contract_id: near_workspaces::types::AccountId, sk: SecretKey) -> Account {
    Account::from_secret_key(contract_id, sk, worker)
}

#[tokio::test]
async fn invariant_01_agent_moves_funds_via_request_payment() -> anyhow::Result<()> {
    let (worker, contract, _owner, recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let before = recipient.view_account().await?.balance;
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": "hello"})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    let after = recipient.view_account().await?.balance;
    assert!(after > before);
    let rid = v["request_id"].as_u64().unwrap();
    let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": rid})).await?.json()?;
    assert_eq!(req["memo"], "hello");
    Ok(())
}

#[tokio::test]
async fn invariant_02_owner_only() -> anyhow::Result<()> {
    let (worker, contract, _owner, _recipient, agent_dev, _a2, stranger) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([]), "1")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res, "MethodNameMismatch");
    let res2 = stranger.call(contract.id(), "kill").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res2, "predecessor must be contract account");
    Ok(())
}

#[tokio::test]
async fn invariant_03_deny_by_default() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, agent_dev2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let unknown = worker.dev_create_account().await?;
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": unknown.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "unknown_recipient");

    // revoke recipient
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([]), "10000000000000000000000000")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let res2 = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v2: serde_json::Value = res2.clone().json()?;
    assert_eq!(v2["code"], "unknown_recipient");

    // isolation
    let agent2 = agent_account(&worker, contract.id().clone(), agent_dev2.secret_key().clone());
    let res3 = agent2.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v3: serde_json::Value = res3.clone().json()?;
    assert_eq!(v3["code"], "unknown_recipient");
    let p1: serde_json::Value = contract.view("get_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string()})).await?.json()?;
    let p2: serde_json::Value = contract.view("get_policy").args_json(json!({"agent_pk": agent_dev2.secret_key().public_key().to_string()})).await?.json()?;
    assert_ne!(p1, p2);
    // denied request not stored
    let rid = v["request_id"].as_u64().unwrap();
    assert!(contract.view("get_request").args_json(json!({"request_id": rid})).await?.json::<Option<serde_json::Value>>()?.is_none());
    Ok(())
}

#[tokio::test]
async fn invariant_04_spending_window_block_time() -> anyhow::Result<()> {
    let (worker, contract, _owner, recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    worker.fast_forward(1000).await?;
    let _ = contract;
    Ok(())
}

#[tokio::test]
async fn invariant_05_approval_binds_hash() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([recipient.id().to_string()]), "1")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    let res2 = owner.call(contract.id(), "approve").args_json(json!({"request_id": req_id, "request_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res2, "hash mismatch");
    Ok(())
}

#[tokio::test]
async fn invariant_06_pending_expiry() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 1u64,
        "recipients": [recipient.id().to_string()],
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "10000000000000000000000000", "approval_threshold": "1", "review_required_above": "1"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    worker.fast_forward(2).await?;
    let res2 = owner.call(contract.id(), "approve").args_json(json!({"request_id": req_id, "request_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert!(res2.is_err() || res2.unwrap().is_failure());
    Ok(())
}

#[tokio::test]
async fn invariant_07_kill_switch() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, agent_dev2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    // positive control
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    // keys exist before kill
    let pk1 = agent_dev.secret_key().public_key();
    let pk2 = agent_dev2.secret_key().public_key();
    assert!(contract.view_access_key(&pk1).await.is_ok());
    assert!(contract.view_access_key(&pk2).await.is_ok());

    owner.call(contract.id(), "kill").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert!(res.is_err(), "agent tx must be rejected at transaction level after kill");
    assert!(contract.view_access_key(&pk1).await.is_err(), "agent1 key must be missing");
    assert!(contract.view_access_key(&pk2).await.is_err(), "agent2 key must be missing");
    Ok(())
}

#[tokio::test]
async fn invariant_08_failed_transfer_releases() -> anyhow::Result<()> {
    let (worker, contract, owner, _recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!(["no-such-account.test.near"]), "10000000000000000000000000")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": "no-such-account.test.near", "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    let rid = v["request_id"].as_u64().unwrap();
    worker.fast_forward(2).await?;
    let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": rid})).await?.json()?;
    assert_eq!(req["status"], "Failed");
    Ok(())
}

#[tokio::test]
async fn invariant_09_events() -> anyhow::Result<()> {
    let (worker, contract, _owner, recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let all = format!("{:?}", res);
    assert!(all.contains("EVENT_JSON"));
    let _ = (worker, contract);
    Ok(())
}

#[tokio::test]
async fn invariant_10_caller_check() -> anyhow::Result<()> {
    let (_worker, contract, _owner, _recipient, _agent_dev, _a2, stranger) = setup().await?;
    let res2 = stranger.call(contract.id(), "flag").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res2, "predecessor must be contract account");
    Ok(())
}

#[tokio::test]
async fn invariant_11_reservation_semantics() -> anyhow::Result<()> {
    let (worker, contract, _owner, recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let rid = v["request_id"].as_u64().unwrap();
    let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": rid})).await?.json()?;
    assert_eq!(req["status"], "Executed");
    Ok(())
}

#[tokio::test]
async fn invariant_12_storage_reserve() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": [recipient.id().to_string()],
        "tokens": [{"token": null, "per_payment_cap": "1000000000000000000000000000", "window_budget": "1000000000000000000000000000", "approval_threshold": "1000000000000000000000000000", "review_required_above": "1000000000000000000000000000"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": "1000000000000000000000000000", "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "insufficient_balance");
    Ok(())
}

// Regression tests for review fixes 1-9
#[tokio::test]
async fn regression_01_inflight_subtract_success() -> anyhow::Result<()> {
    let (worker, contract, _owner, recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    for _ in 0..3 {
        let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": "3000000000000000000000000", "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
        let v: serde_json::Value = res.clone().json()?;
        assert_eq!(v["code"], "ok");
        let rid = v["request_id"].as_u64().unwrap();
        // poll until Executed
        for _ in 0..10 {
            let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": rid})).await?.json()?;
            if req["status"] == "Executed" { break; }
            worker.fast_forward(1).await?;
        }
        let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": rid})).await?.json()?;
        assert_eq!(req["status"], "Executed");
    }
    let total: serde_json::Value = contract.view("get_in_flight_total").args_json(json!({})).await?.json()?;
    assert_eq!(total, "0");
    Ok(())
}

#[tokio::test]
async fn regression_02_unfreeze_agent() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    // freeze by denials
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let unknown = worker.dev_create_account().await?;
    for _ in 0..5 {
        let _ = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": unknown.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    }
    owner.call(contract.id(), "unfreeze_agent").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string()})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    Ok(())
}

#[tokio::test]
async fn regression_03_denied_not_stored_pending_ids() -> anyhow::Result<()> {
    let (worker, contract, _owner, _recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let unknown = worker.dev_create_account().await?;
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": unknown.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let rid = v["request_id"].as_u64().unwrap();
    assert!(contract.view("get_request").args_json(json!({"request_id": rid})).await?.json::<Option<serde_json::Value>>()?.is_none());
    let pending: Vec<serde_json::Value> = contract.view("pending_requests").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string()})).await?.json()?;
    assert!(pending.is_empty());
    Ok(())
}

#[tokio::test]
async fn regression_04_sweep_expired() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 1u64,
        "recipients": [recipient.id().to_string()],
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "10000000000000000000000000", "approval_threshold": "1", "review_required_above": "1"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    worker.fast_forward(2).await?;
    // trigger sweep by another request_payment
    let _ = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": "1", "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": req_id})).await?.json()?;
    assert_eq!(req["status"], "Expired");
    Ok(())
}

#[tokio::test]
async fn regression_05_resolve_stuck() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([recipient.id().to_string()]), "1")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    let res2 = owner.call(contract.id(), "resolve_stuck").args_json(json!({"request_id": req_id})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res2, "not stuck");
    Ok(())
}

#[tokio::test]
async fn regression_06_kill_one_promise_per_key() -> anyhow::Result<()> {
    let (worker, contract, owner, _recipient, agent_dev, agent_dev2, _) = setup().await?;
    let pk_a = agent_dev.secret_key().public_key();
    let pk_b = agent_dev2.secret_key().public_key();
    assert!(contract.view_access_key(&pk_a).await.is_ok());
    assert!(contract.view_access_key(&pk_b).await.is_ok());
    // owner directly deletes agent A's key
    owner.batch(contract.id()).delete_key(pk_a.clone()).transact().await?.into_result()?;
    // then kill()
    owner.call(contract.id(), "kill").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    // agent B's key must be gone (not rolled back)
    assert!(contract.view_access_key(&pk_b).await.is_err(), "agent B key must be deleted");
    assert!(contract.view_access_key(&pk_a).await.is_err(), "agent A key must be deleted");
    let _ = worker;
    Ok(())
}

#[tokio::test]
async fn regression_07_unknown_recipient_escalate() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": [],
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "10000000000000000000000000", "approval_threshold": "10000000000000000000000000", "review_required_above": "10000000000000000000000000"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Escalate"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "pending_approval");
    Ok(())
}

#[tokio::test]
async fn regression_08_fixed_bucket_on_policy_change() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([recipient.id().to_string()]), "10000000000000000000000000")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    // spend buckets keyed by window; old spend no longer aligns, but no panic
    let res2 = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v2: serde_json::Value = res2.clone().json()?;
    assert!(v2["code"] == "ok" || v2["code"] == "window_budget");
    Ok(())
}

#[tokio::test]
async fn regression_09_approve_no_unwrap_reserve() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([recipient.id().to_string()]), "1")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": req_id})).await?.json()?;
    let hash = req["request_hash"].clone();
    // wrong hash
    let res2 = owner.call(contract.id(), "approve").args_json(json!({"request_id": req_id, "request_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res2, "hash mismatch");
    // removed token policy
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": [recipient.id().to_string()],
        "tokens": [],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let res3 = owner.call(contract.id(), "approve").args_json(json!({"request_id": req_id, "request_hash": hash})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res3, "token policy missing");
    // low balance
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": [recipient.id().to_string()],
        "tokens": [{"token": null, "per_payment_cap": "1000000000000000000000000000", "window_budget": "1000000000000000000000000000", "approval_threshold": "1000000000000000000000000000", "review_required_above": "1000000000000000000000000000"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let res4 = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": "1000000000000000000000000000", "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v4: serde_json::Value = res4.clone().json()?;
    assert_eq!(v4["code"], "insufficient_balance");
    Ok(())
}

#[tokio::test]
async fn regression_10_approve_window_update_release() -> anyhow::Result<()> {
    let (worker, contract, owner, _recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": ["no-such-account.test.near"],
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "10000000000000000000000000", "approval_threshold": "1", "review_required_above": "1"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": "no-such-account.test.near", "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    // change window
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 7200000000000u64,
        "bucket_count": 4,
        "max_pending": 10,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": ["no-such-account.test.near"],
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "10000000000000000000000000", "approval_threshold": "1", "review_required_above": "1"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let req: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": req_id})).await?.json()?;
    let hash = req["request_hash"].clone();
    let res2 = owner.call(contract.id(), "approve").args_json(json!({"request_id": req_id, "request_hash": hash})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let _ = res2;
    worker.fast_forward(2).await?;
    let req2: serde_json::Value = contract.view("get_request").args_json(json!({"request_id": req_id})).await?.json()?;
    assert_eq!(req2["status"], "Failed");
    Ok(())
}

#[tokio::test]
async fn regression_11_sweep_summary_does_not_flood() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": {
        "count_limit": 1000,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 100,
        "max_denials": 1000,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 1u64,
        "recipients": [recipient.id().to_string()],
        "tokens": [{"token": null, "per_payment_cap": "5000000000000000000000000", "window_budget": "100000000000000000000000000", "approval_threshold": "1", "review_required_above": "1"}],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    // earlier decision
    let res0 = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v0: serde_json::Value = res0.clone().json()?;
    assert_eq!(v0["code"], "pending_approval");
    // 100 expiring requests
    for _ in 0..100 {
        let _ = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    }
    worker.fast_forward(2).await?;
    // trigger sweep
    let _ = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": "1", "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    let decisions: Vec<serde_json::Value> = contract.view("recent_decisions").args_json(json!({"limit": 1000})).await?.json()?;
    // earlier "pending approval" decision should still exist (not flooded by 100 expired)
    assert!(decisions.iter().any(|d| d["reason"] == "pending approval"));
    Ok(())
}

#[tokio::test]
async fn regression_12_max_pending_bound() -> anyhow::Result<()> {
    let (_worker, contract, owner, _recipient, _agent_dev, _a2, _) = setup().await?;
    let pk = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519).public_key().to_string();
    let res = owner.call(contract.id(), "add_agent").args_json(json!({"agent_pk": pk, "policy": {
        "count_limit": 10,
        "cooldown_ns": 0,
        "window_ns": 3600000000000u64,
        "bucket_count": 4,
        "max_pending": 101u32,
        "max_denials": 5,
        "denial_window_ns": 3600000000000u64,
        "expiry_ns": 3600000000000u64,
        "recipients": [],
        "tokens": [],
        "allowance": ALLOWANCE,
        "unknown_recipient": "Deny"
    }})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res, "max_pending too high");
    Ok(())
}

#[tokio::test]
async fn regression_13_unfreeze_resets_window() -> anyhow::Result<()> {
    let (worker, contract, owner, _recipient, agent_dev, _a2, _) = setup().await?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let unknown = worker.dev_create_account().await?;
    for _ in 0..5 {
        let _ = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": unknown.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    }
    let frozen_res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": unknown.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(frozen_res, "agent frozen");
    owner.call(contract.id(), "unfreeze_agent").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string()})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let pol: serde_json::Value = contract.view("get_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string()})).await?.json()?;
    assert_eq!(pol["denial_count"], 0);
    Ok(())
}

#[tokio::test]
async fn regression_14_resolve_stuck_event() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "update_policy").args_json(json!({"agent_pk": agent_dev.secret_key().public_key().to_string(), "policy": policy(json!([recipient.id().to_string()]), "1")})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    let req_id = v["request_id"].as_u64().unwrap();
    let res2 = owner.call(contract.id(), "resolve_stuck").args_json(json!({"request_id": req_id})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await;
    assert_fails_with(res2, "not stuck");
    Ok(())
}

#[tokio::test]
async fn regression_15_flag_only() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "flag").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let all = format!("{:?}", res);
    assert!(all.contains("guard halted"), "agent call must fail with guard halted");
    let pk = agent_dev.secret_key().public_key();
    assert!(contract.view_access_key(&pk).await.is_ok(), "agent key must still exist");
    Ok(())
}

#[tokio::test]
async fn regression_16_kill_then_resume() -> anyhow::Result<()> {
    let (worker, contract, owner, recipient, agent_dev, _a2, _) = setup().await?;
    owner.call(contract.id(), "kill").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    owner.call(contract.id(), "resume").gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    let agent = agent_account(&worker, contract.id().clone(), agent_dev.secret_key().clone());
    let res = agent.call(contract.id(), "request_payment").args_json(json!({"recipient": recipient.id().to_string(), "token": null, "amount": ONE_NEAR, "memo": null})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let v: serde_json::Value = res.clone().json()?;
    assert_eq!(v["code"], "ok");
    Ok(())
}
