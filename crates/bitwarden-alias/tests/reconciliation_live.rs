//! Live reconciliation contract test for a disposable SimpleLogin checkout.
//!
//! Run with:
//! `SIMPLELOGIN_API_URL=... SIMPLELOGIN_API_TOKEN=... cargo test -p bitwarden-alias --test reconciliation_live -- --ignored`

use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_alias::{
    ALIAS_REFERENCE_VERSION, AliasClient, AliasClientSettings, AliasId, AliasProvider,
    AliasReconciliationOutcome, AliasReference, CreateRandomAliasRequest,
    apply_alias_reconciliation, plan_alias_reconciliation,
};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{CipherId, CipherRepromptType, CipherType, CipherView, LoginView};

#[tokio::test]
#[ignore = "requires a disposable SimpleLogin server and API token"]
async fn reconciles_real_simplelogin_with_real_vault_models() {
    let api_url = std::env::var("SIMPLELOGIN_API_URL")
        .expect("SIMPLELOGIN_API_URL must point at the disposable SimpleLogin checkout");
    let api_token = std::env::var("SIMPLELOGIN_API_TOKEN")
        .expect("SIMPLELOGIN_API_TOKEN must belong to the disposable SimpleLogin account");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let client = AliasClient::new(
        AliasClientSettings::new(SensitiveString::from(api_token))
            .with_base_url(api_url)
            .with_connection_id("11111111-1111-4111-8111-111111111111".to_owned()),
    )
    .expect("live SimpleLogin client should be constructible");

    let alias = client
        .create_random_alias(CreateRandomAliasRequest {
            hostname: Some(SensitiveString::from(format!(
                "reconcile-{unique}.integration.test"
            ))),
            mode: None,
            note: Some(SensitiveString::from(format!(
                "sdk-reconciliation-{unique}"
            ))),
        })
        .await
        .expect("real alias creation should succeed");
    let alias_id = alias.id;
    let provider = client
        .provider_identity()
        .expect("live client should have a connection identity");
    let cipher_id = CipherId::new_v4();
    let mut ciphers = vec![login_cipher(cipher_id, alias.email.expose().to_owned())];
    client
        .alias_reference(&alias)
        .expect("live alias should produce a current reference")
        .bind_to_cipher(&mut ciphers[0])
        .expect("current reference should bind to the live cipher model");

    let dry_run = plan_alias_reconciliation(&provider, std::slice::from_ref(&alias), &ciphers)
        .expect("real provider data should reconcile");
    assert_eq!(dry_run.summary.matched, 1);
    assert_eq!(dry_run.summary.proposed_repairs, 0);

    let stored = AliasReference::from_cipher(&ciphers[0])
        .expect("stored live reference should be valid")
        .expect("stored live reference should exist");
    assert_eq!(stored.alias_id, alias_id);
    assert_eq!(stored.provider_identity(), provider);

    let serialized = serde_json::to_vec(&ciphers[0]).expect("real CipherView should serialize");
    let restored: CipherView =
        serde_json::from_slice(&serialized).expect("real CipherView should deserialize");
    assert_eq!(
        AliasReference::from_cipher(&restored)
            .expect("round-tripped reference should parse")
            .expect("round-tripped reference should exist")
            .alias_id,
        alias_id
    );

    let mut stale = client
        .alias_reference(&alias)
        .expect("live alias should produce a reference");
    stale.address = SensitiveString::from(format!("stale-{unique}@example.test"));
    stale
        .bind_to_cipher(&mut ciphers[0])
        .expect("stale fixture should attach");
    let stale_plan = plan_alias_reconciliation(&provider, std::slice::from_ref(&alias), &ciphers)
        .expect("stale binding should reconcile");
    assert!(matches!(
        stale_plan.outcomes.as_slice(),
        [AliasReconciliationOutcome::StaleBinding {
            alias_id: found_alias_id,
            cipher_id: found_cipher_id,
            reference_address_stale: true,
            username_stale: true,
        }] if *found_alias_id == alias_id && *found_cipher_id == cipher_id
    ));
    apply_alias_reconciliation(&stale_plan, std::slice::from_ref(&alias), &mut ciphers)
        .expect("stale binding repair should succeed");

    let mut duplicate = ciphers[0].clone();
    duplicate.id = Some(CipherId::new_v4());
    let duplicate_plan = plan_alias_reconciliation(
        &provider,
        std::slice::from_ref(&alias),
        &[ciphers[0].clone(), duplicate],
    )
    .expect("duplicate bindings should be reported");
    assert_eq!(duplicate_plan.summary.duplicate_bindings, 1);
    assert!(duplicate_plan.actions.is_empty());

    let mut missing = login_cipher(CipherId::new_v4(), "missing@example.test".to_owned());
    AliasReference {
        version: ALIAS_REFERENCE_VERSION,
        provider: AliasProvider::SimpleLogin,
        provider_instance: provider.instance.clone(),
        connection_id: provider.connection_id.clone(),
        alias_id: AliasId(alias_id.0 + 1_000_000),
        address: SensitiveString::from("missing@example.test"),
    }
    .bind_to_cipher(&mut missing)
    .expect("missing reference fixture should attach");
    let missing_plan =
        plan_alias_reconciliation(&provider, std::slice::from_ref(&alias), &[missing])
            .expect("missing provider aliases should be reported");
    assert_eq!(missing_plan.summary.missing_aliases, 1);
    assert!(missing_plan.actions.is_empty());

    let deleted = client
        .delete_alias(alias_id)
        .await
        .expect("real alias cleanup should succeed");
    assert!(deleted.deleted);
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
