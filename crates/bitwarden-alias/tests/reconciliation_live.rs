//! Live provider-neutral contract test against the pinned disposable SimpleLogin checkout.
//!
//! Run with `SIMPLELOGIN_API_URL=... SIMPLELOGIN_API_TOKEN=... cargo test -p
//! bitwarden-alias --test reconciliation_live -- --ignored`.

use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_alias::{
    AliasClient, AliasReconciliationOutcome, CreateAliasRequest, SimpleLoginAdapter,
    SimpleLoginAdapterSettings, bind_alias_reference, create_alias_reference,
    plan_alias_reconciliation,
};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{CipherId, CipherRepromptType, CipherType, CipherView, LoginView};

const CONNECTION_ID: &str = "11111111-1111-4111-8111-111111111111";

#[tokio::test]
#[ignore = "requires the pinned disposable SimpleLogin server and API token"]
async fn real_adapter_refines_the_provider_neutral_contract() {
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
    .expect("adapter settings should be valid");
    let client = AliasClient::new(std::sync::Arc::new(adapter))
        .expect("neutral client should accept the concrete adapter");

    let alias = client
        .create(CreateAliasRequest {
            hostname: Some(SensitiveString::from(format!(
                "reconcile-{unique}.integration.test"
            ))),
        })
        .await
        .expect("real alias creation should succeed");
    assert_eq!(alias.identity.connection_id, CONNECTION_ID);
    assert!(!alias.identity.alias_id.is_empty());

    let cipher_id = CipherId::new_v4();
    let cipher = login_cipher(cipher_id, alias.identity.address.expose().to_owned());
    let encoded = create_alias_reference(&alias.identity).expect("reference should encode");
    let bound = bind_alias_reference(encoded.expose(), cipher)
        .expect("canonical identity should bind to a matching login");
    assert!(bound.changed);
    let ciphers = vec![bound.cipher];

    let plan = plan_alias_reconciliation(CONNECTION_ID, std::slice::from_ref(&alias), &ciphers)
        .expect("real adapter data should reconcile");
    assert_eq!(plan.summary.matched, 1);
    assert!(matches!(
        plan.outcomes.as_slice(),
        [AliasReconciliationOutcome::Matched { alias_id, cipher_id: found }]
            if alias_id == &alias.identity.alias_id && *found == cipher_id
    ));

    let fetched = client
        .get(alias.identity.clone())
        .await
        .expect("opaque identity should retrieve the same resource");
    assert_eq!(fetched.identity.connection_id, alias.identity.connection_id);
    assert_eq!(fetched.identity.alias_id, alias.identity.alias_id);

    let deleted = client
        .delete(alias.identity)
        .await
        .expect("real alias cleanup should succeed");
    assert!(deleted.deleted);
    assert_eq!(
        ciphers[0].id,
        Some(cipher_id),
        "provider delete preserves vault"
    );
}

fn login_cipher(id: CipherId, username: String) -> CipherView {
    let timestamp = "2026-08-10T10:00:00Z"
        .parse()
        .expect("test timestamp should parse");
    CipherView {
        id: Some(id),
        organization_id: None,
        folder_id: None,
        collection_ids: Vec::new(),
        key: None,
        name: "Live alias login".to_owned(),
        notes: None,
        r#type: CipherType::Login,
        login: Some(LoginView {
            username: Some(username),
            password: None,
            alias_reference: None,
            password_revision_date: None,
            uris: None,
            totp: None,
            autofill_on_page_load: None,
            fido2_credentials: None,
        }),
        identity: None,
        card: None,
        secure_note: None,
        ssh_key: None,
        bank_account: None,
        drivers_license: None,
        passport: None,
        favorite: false,
        reprompt: CipherRepromptType::None,
        organization_use_totp: false,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        attachment_decryption_failures: None,
        fields: None,
        password_history: None,
        creation_date: timestamp,
        deleted_date: None,
        revision_date: timestamp,
        archived_date: None,
    }
}
