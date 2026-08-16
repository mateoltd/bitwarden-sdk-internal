//! Live refinement test for the concrete adapter against the pinned disposable SimpleLogin lab.
//!
//! Run with `SIMPLELOGIN_API_URL=... SIMPLELOGIN_API_TOKEN=... cargo test -p
//! bitwarden-alias --test simplelogin_live -- --ignored`.

use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_alias::{
    AliasClient, AliasLifecycleState, CreateAliasRequest, CreateSendReplyIdentityRequest,
    ListAliasesRequest, SimpleLoginAdapter, SimpleLoginAdapterSettings,
};
use bitwarden_sensitive_value::SensitiveString;

const CONNECTION_ID: &str = "11111111-1111-4111-8111-111111111111";
static LIVE_ACCOUNT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
#[ignore = "requires the pinned disposable SimpleLogin server and API token"]
async fn complete_provider_neutral_lifecycle_against_real_simplelogin() {
    let _account_guard = LIVE_ACCOUNT_LOCK.lock().await;
    let (client, unique) = live_client();
    let alias = client
        .create(CreateAliasRequest {
            hostname: Some(SensitiveString::from(format!(
                "sdk-{unique}.integration.test"
            ))),
        })
        .await
        .expect("real create should succeed");
    assert_eq!(alias.identity.connection_id, CONNECTION_ID);
    assert!(!alias.identity.alias_id.is_empty());

    let listed = client
        .list(ListAliasesRequest::default())
        .await
        .expect("real list should succeed");
    assert!(listed.aliases.iter().any(|candidate| {
        candidate.identity.connection_id == alias.identity.connection_id
            && candidate.identity.alias_id == alias.identity.alias_id
    }));
    let detail = client
        .get(alias.identity.clone())
        .await
        .expect("real get should succeed");
    assert_eq!(detail.identity.alias_id, alias.identity.alias_id);

    let disabled = client
        .set_enabled(alias.identity.clone(), false)
        .await
        .expect("real disable should converge");
    assert_eq!(disabled.lifecycle, AliasLifecycleState::Disabled);
    let enabled = client
        .set_enabled(alias.identity.clone(), true)
        .await
        .expect("real enable should converge");
    assert_eq!(enabled.lifecycle, AliasLifecycleState::Enabled);

    let send_reply = client
        .create_send_reply_identity(CreateSendReplyIdentityRequest {
            alias: alias.identity.clone(),
            recipient: SensitiveString::from(format!("recipient-{unique}@example.net")),
        })
        .await
        .expect("real send/reply identity creation should succeed");
    let identities = client
        .list_send_reply_identities(alias.identity.clone(), None)
        .await
        .expect("real send/reply identities should list");
    assert!(
        identities
            .identities
            .iter()
            .any(|identity| identity.identity_id == send_reply.identity_id)
    );
    let blocked = client
        .set_send_reply_blocked(send_reply, true)
        .await
        .expect("real send/reply block should converge");
    assert_eq!(blocked.blocked, Some(true));
    let unblocked = client
        .set_send_reply_blocked(blocked, false)
        .await
        .expect("real send/reply unblock should converge");
    assert_eq!(unblocked.blocked, Some(false));
    client
        .remove_send_reply_identity(unblocked)
        .await
        .expect("real send/reply identity removal should succeed");

    let deleted = client
        .delete(alias.identity.clone())
        .await
        .expect("real delete should succeed");
    assert!(deleted.deleted);
    let repeated = client
        .delete(alias.identity)
        .await
        .expect("already-absent delete should be idempotent");
    assert!(repeated.deleted);
}

#[tokio::test]
#[ignore = "requires the pinned disposable SimpleLogin server and API token"]
async fn concurrent_explicit_state_converges_against_real_simplelogin() {
    let _account_guard = LIVE_ACCOUNT_LOCK.lock().await;
    let (first, unique) = live_client();
    let (second, _) = live_client();
    let alias = first
        .create(CreateAliasRequest {
            hostname: Some(SensitiveString::from(format!(
                "concurrent-{unique}.integration.test"
            ))),
        })
        .await
        .expect("real create should succeed");

    let (first_result, second_result) = tokio::join!(
        first.set_enabled(alias.identity.clone(), false),
        second.set_enabled(alias.identity.clone(), false)
    );
    assert_eq!(
        first_result
            .expect("first disable should succeed")
            .lifecycle,
        AliasLifecycleState::Disabled
    );
    assert_eq!(
        second_result
            .expect("second disable should be idempotent")
            .lifecycle,
        AliasLifecycleState::Disabled
    );
    assert_eq!(
        first
            .get(alias.identity.clone())
            .await
            .expect("detail should remain readable")
            .lifecycle,
        AliasLifecycleState::Disabled
    );
    first
        .delete(alias.identity)
        .await
        .expect("cleanup should succeed");
}

fn live_client() -> (AliasClient, u128) {
    let api_url = std::env::var("SIMPLELOGIN_API_URL")
        .expect("SIMPLELOGIN_API_URL must point at the disposable checkout");
    let api_token = std::env::var("SIMPLELOGIN_API_TOKEN")
        .expect("SIMPLELOGIN_API_TOKEN must belong to its disposable account");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let adapter = SimpleLoginAdapter::new(SimpleLoginAdapterSettings::new(
        CONNECTION_ID.to_owned(),
        api_url,
        SensitiveString::from(api_token),
    ))
    .expect("live adapter should be constructible");
    (
        adapter
            .into_client()
            .expect("adapter must satisfy the common contract"),
        unique,
    )
}
