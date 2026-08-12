//! Executable refinement checks for the machine-checked alias security model.

use std::{
    io::Read,
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bitwarden_alias::{
    ALIAS_REFERENCE_FIELD_NAME, ALIAS_REFERENCE_VERSION, Alias, AliasClient, AliasClientSettings,
    AliasError, AliasId, AliasProviderIdentity, MailboxId, MailboxRef, apply_alias_reconciliation,
    create_alias_reference, migrate_alias_reference, parse_alias_reference,
    plan_alias_reconciliation,
};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{
    CipherRepromptType, CipherType, CipherView, FieldType, FieldView, LoginView,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

const VECTORS: &str = include_str!("../../../formal/alias-security/conformance-vectors.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    contract_version: u32,
    model_revision: String,
    model_files: Vec<String>,
    model_sha256: String,
    reference_schema: ReferenceSchema,
    identities: Identities,
    reference_vectors: Vec<ReferenceVector>,
    migration_vectors: Vec<MigrationVector>,
    reconciliation_vectors: Vec<ReconciliationVector>,
    lifecycle_traces: Vec<LifecycleTrace>,
    operation_semantics: OperationSemantics,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceSchema {
    version: u32,
    legacy_version: u32,
    vault_field_name: String,
    ordered_fields: Vec<String>,
    forbidden_fields: Vec<String>,
    credential_sentinel: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identities {
    primary: Identity,
    same_origin_second_account: Identity,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    provider: String,
    instance: String,
    connection_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceVector {
    name: String,
    identity: String,
    alias_id: u64,
    address: String,
    expected_canonical: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MigrationVector {
    name: String,
    input: String,
    connections: Vec<String>,
    expected_canonical: Option<String>,
    expected_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationVector {
    name: String,
    identity: String,
    aliases: Vec<AliasFixture>,
    ciphers: Vec<CipherFixture>,
    expected: ReconciliationExpected,
}

#[derive(Deserialize)]
struct AliasFixture {
    id: u64,
    address: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherFixture {
    id: String,
    username: String,
    name: String,
    notes: String,
    custom_field_name: String,
    custom_field_value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationExpected {
    proposed_repairs: u64,
    changed_cipher_ids: Vec<String>,
    unchanged_actions_on_replay: u64,
    actions_after_replan: usize,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleTrace {
    name: String,
    alias_id: u64,
    desired_enabled: bool,
    initial_enabled: bool,
    steps: Vec<LifecycleStep>,
    expected_enabled: Option<bool>,
    expected_error: Option<String>,
    expected_toggle_count: usize,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleStep {
    kind: String,
    provider_enabled_after: bool,
    response_enabled: Option<bool>,
}

#[derive(Deserialize)]
struct OperationSemantics {
    disable: DisableSemantics,
    delete: DeleteSemantics,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DisableSemantics {
    provider_resource: String,
    vault_cipher: String,
    success_evidence: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteSemantics {
    confirmed_alias_id: u64,
    unknown_alias_id: u64,
    provider_resource: String,
    vault_cipher: String,
    transport_failure: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("formal conformance vectors must be valid")
}

fn identity(fixture: &Identity) -> AliasProviderIdentity {
    assert_eq!(fixture.provider, "simplelogin");
    AliasProviderIdentity::simplelogin(&fixture.instance, &fixture.connection_id)
        .expect("formal identity must be valid")
}

fn select_identity<'a>(vectors: &'a Vectors, name: &str) -> &'a Identity {
    match name {
        "primary" => &vectors.identities.primary,
        "sameOriginSecondAccount" => &vectors.identities.same_origin_second_account,
        _ => panic!("unknown formal identity {name}"),
    }
}

fn alias(id: u64, address: &str) -> Alias {
    let mailbox = MailboxRef {
        id: MailboxId(1),
        email: SensitiveString::from("owner@example.test"),
    };
    Alias {
        id: AliasId(id),
        email: SensitiveString::from(address),
        creation_date: "2026-08-12T00:00:00Z".to_owned(),
        creation_timestamp: 1,
        enabled: true,
        note: None,
        name: None,
        nb_forward: 0,
        nb_block: 0,
        nb_reply: 0,
        mailbox,
        mailboxes: Vec::new(),
        support_pgp: false,
        disable_pgp: false,
        latest_activity: None,
        pinned: false,
    }
}

fn cipher(fixture: &CipherFixture) -> CipherView {
    let timestamp = "2026-08-12T00:00:00Z"
        .parse()
        .expect("fixture timestamp must parse");
    CipherView {
        id: Some(fixture.id.parse().expect("fixture cipher ID must parse")),
        organization_id: None,
        folder_id: None,
        collection_ids: Vec::new(),
        key: None,
        name: fixture.name.clone(),
        notes: Some(fixture.notes.clone()),
        r#type: CipherType::Login,
        login: Some(LoginView {
            username: Some(fixture.username.clone()),
            password: Some("unrelated-password".to_owned()),
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
        favorite: true,
        reprompt: CipherRepromptType::None,
        organization_use_totp: false,
        edit: true,
        permissions: None,
        view_password: true,
        local_data: None,
        attachments: None,
        attachment_decryption_failures: None,
        fields: Some(vec![FieldView {
            name: Some(fixture.custom_field_name.clone()),
            value: Some(fixture.custom_field_value.clone()),
            r#type: FieldType::Text,
            linked_id: None,
        }]),
        password_history: None,
        creation_date: timestamp,
        deleted_date: None,
        revision_date: timestamp,
        archived_date: None,
    }
}

fn unrelated_projection(cipher: &CipherView) -> Value {
    let mut value = serde_json::to_value(cipher).expect("cipher projection must serialize");
    if let Some(login) = value.get_mut("login").and_then(Value::as_object_mut) {
        login.insert("username".to_owned(), Value::Null);
    }
    if let Some(fields) = value.get_mut("fields").and_then(Value::as_array_mut) {
        fields.retain(|field| {
            field.get("name").and_then(Value::as_str) != Some(ALIAS_REFERENCE_FIELD_NAME)
        });
    }
    value
}

fn alias_json(id: u64, enabled: bool) -> Value {
    json!({
        "id": id,
        "email": format!("alias-{id}@sl.test"),
        "creation_date": "2026-08-12T00:00:00Z",
        "creation_timestamp": 1,
        "enabled": enabled,
        "note": null,
        "name": null,
        "nb_forward": 0,
        "nb_block": 0,
        "nb_reply": 0,
        "mailbox": {"id": 1, "email": "owner@example.test"},
        "mailboxes": [{"id": 1, "email": "owner@example.test"}],
        "support_pgp": false,
        "disable_pgp": false,
        "latest_activity": null,
        "pinned": false
    })
}

#[test]
fn production_reference_schema_refines_the_formal_contract() {
    let vectors = vectors();
    assert_eq!(vectors.contract_version, 1);
    assert_eq!(vectors.model_revision, "alias-security-v1");
    assert_eq!(
        vectors.model_files,
        [
            "AliasVault.tla",
            "AliasVault.cfg",
            "AliasLifecycle.tla",
            "AliasLifecycle.cfg",
            "AliasLifecycleQuiescent.cfg",
        ]
    );
    let mut model = Sha256::new();
    model.update(include_bytes!(
        "../../../formal/alias-security/AliasVault.tla"
    ));
    model.update(include_bytes!(
        "../../../formal/alias-security/AliasVault.cfg"
    ));
    model.update(include_bytes!(
        "../../../formal/alias-security/AliasLifecycle.tla"
    ));
    model.update(include_bytes!(
        "../../../formal/alias-security/AliasLifecycle.cfg"
    ));
    model.update(include_bytes!(
        "../../../formal/alias-security/AliasLifecycleQuiescent.cfg"
    ));
    let model_sha256 = model
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(model_sha256, vectors.model_sha256);
    assert_eq!(vectors.reference_schema.version, ALIAS_REFERENCE_VERSION);
    assert_eq!(vectors.reference_schema.legacy_version, 1);
    assert_eq!(
        vectors.reference_schema.vault_field_name,
        ALIAS_REFERENCE_FIELD_NAME
    );

    for vector in &vectors.reference_vectors {
        let provider = identity(select_identity(&vectors, &vector.identity));
        let encoded = create_alias_reference(&provider, &alias(vector.alias_id, &vector.address))
            .expect("proved reference vector must encode");
        assert_eq!(
            encoded.expose().as_str(),
            vector.expected_canonical,
            "{}",
            vector.name
        );
        let parsed =
            parse_alias_reference(encoded.expose()).expect("proved reference vector must parse");
        assert_eq!(parsed.provider_identity(), provider, "{}", vector.name);
        assert_eq!(parsed.alias_id, AliasId(vector.alias_id), "{}", vector.name);
        assert_eq!(parsed.encode().expect("reference must re-encode"), encoded);

        let value: Value = serde_json::from_str(encoded.expose()).expect("canonical JSON");
        let keys: Vec<_> = value
            .as_object()
            .expect("reference must be an object")
            .keys()
            .cloned()
            .collect();
        let mut expected_keys = vectors.reference_schema.ordered_fields.clone();
        expected_keys.sort();
        assert_eq!(keys, expected_keys, "{}", vector.name);
        for forbidden in &vectors.reference_schema.forbidden_fields {
            assert!(!value.as_object().expect("object").contains_key(forbidden));
        }
        assert!(
            !encoded
                .expose()
                .contains(&vectors.reference_schema.credential_sentinel)
        );
    }

    let vector = &vectors.reference_vectors[0];
    let mut hostile: Value =
        serde_json::from_str(&vector.expected_canonical).expect("canonical JSON");
    hostile["apiToken"] = Value::String(vectors.reference_schema.credential_sentinel.clone());
    let hostile = hostile.to_string();
    let error = parse_alias_reference(&hostile).expect_err("credential field must be rejected");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(&vectors.reference_schema.credential_sentinel));
}

#[test]
fn production_migration_refines_unambiguous_and_idempotent_rules() {
    let vectors = vectors();
    for vector in &vectors.migration_vectors {
        let connections: Vec<_> = vector
            .connections
            .iter()
            .map(|name| identity(select_identity(&vectors, name)))
            .collect();
        match (&vector.expected_canonical, &vector.expected_error) {
            (Some(expected), None) => {
                let actual = migrate_alias_reference(&vector.input, &connections)
                    .expect("successful migration vector must migrate");
                assert_eq!(actual.expose(), expected, "{}", vector.name);
            }
            (None, Some(expected)) => {
                let error = migrate_alias_reference(&vector.input, &connections)
                    .expect_err("rejected migration vector must fail");
                assert_eq!(error.to_string(), *expected, "{}", vector.name);
                assert!(!error.to_string().contains("legacy@example.test"));
            }
            _ => panic!("{} has an invalid expected result", vector.name),
        }
    }
}

#[test]
fn production_reconciliation_refines_atomic_idempotent_preservation_rules() {
    let vectors = vectors();
    for vector in &vectors.reconciliation_vectors {
        let provider = identity(select_identity(&vectors, &vector.identity));
        let aliases: Vec<_> = vector
            .aliases
            .iter()
            .map(|fixture| alias(fixture.id, &fixture.address))
            .collect();
        let mut ciphers: Vec<_> = vector.ciphers.iter().map(cipher).collect();
        let before = ciphers.clone();

        let plan = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("proved reconciliation must plan");
        assert_eq!(
            plan.summary.proposed_repairs, vector.expected.proposed_repairs,
            "{}",
            vector.name
        );
        let applied = apply_alias_reconciliation(&plan, &aliases, &mut ciphers)
            .expect("proved reconciliation must apply");
        let changed: Vec<String> = applied
            .changed_cipher_ids
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            changed, vector.expected.changed_cipher_ids,
            "{}",
            vector.name
        );
        assert_eq!(
            unrelated_projection(&ciphers[0]),
            unrelated_projection(&before[0]),
            "{}",
            vector.name
        );
        assert_eq!(
            serde_json::to_value(&ciphers[1]).expect("ordinary cipher must serialize"),
            serde_json::to_value(&before[1]).expect("ordinary cipher must serialize"),
            "{}",
            vector.name
        );

        let replay = apply_alias_reconciliation(&plan, &aliases, &mut ciphers)
            .expect("proved reconciliation replay must be a no-op");
        assert!(replay.changed_cipher_ids.is_empty(), "{}", vector.name);
        assert_eq!(
            replay.unchanged_actions, vector.expected.unchanged_actions_on_replay,
            "{}",
            vector.name
        );
        let replanned = plan_alias_reconciliation(&provider, &aliases, &ciphers)
            .expect("repaired inventory must replan");
        assert_eq!(
            replanned.actions.len(),
            vector.expected.actions_after_replan,
            "{}",
            vector.name
        );
    }
}

#[tokio::test]
async fn production_lifecycle_executes_the_machine_checked_traces() {
    let vectors = vectors();
    for trace in vectors.lifecycle_traces {
        let server = MockServer::start().await;
        let steps = Arc::new(trace.steps.clone());
        let cursor = Arc::new(AtomicUsize::new(0));
        let enabled = Arc::new(AtomicBool::new(trace.initial_enabled));
        let toggles = Arc::new(AtomicUsize::new(0));

        let get_steps = Arc::clone(&steps);
        let get_cursor = Arc::clone(&cursor);
        let get_enabled = Arc::clone(&enabled);
        let alias_id = trace.alias_id;
        Mock::given(matchers::method("GET"))
            .and(matchers::path(format!("/api/aliases/{alias_id}")))
            .respond_with(move |_: &wiremock::Request| {
                let index = get_cursor.fetch_add(1, Ordering::SeqCst);
                let step = &get_steps[index];
                assert_eq!(step.kind, "get", "unexpected trace step {index}");
                get_enabled.store(step.provider_enabled_after, Ordering::SeqCst);
                ResponseTemplate::new(200)
                    .set_body_json(alias_json(alias_id, step.provider_enabled_after))
            })
            .mount(&server)
            .await;

        let toggle_steps = Arc::clone(&steps);
        let toggle_cursor = Arc::clone(&cursor);
        let toggle_enabled = Arc::clone(&enabled);
        let toggle_count = Arc::clone(&toggles);
        Mock::given(matchers::method("POST"))
            .and(matchers::path(format!("/api/aliases/{alias_id}/toggle")))
            .respond_with(move |_: &wiremock::Request| {
                let index = toggle_cursor.fetch_add(1, Ordering::SeqCst);
                let step = &toggle_steps[index];
                assert_eq!(step.kind, "toggle", "unexpected trace step {index}");
                toggle_count.fetch_add(1, Ordering::SeqCst);
                toggle_enabled.store(step.provider_enabled_after, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "enabled": step.response_enabled.expect("toggle response state")
                }))
            })
            .mount(&server)
            .await;

        let client = AliasClient::new(
            AliasClientSettings::new(SensitiveString::from("formal-test-token"))
                .with_base_url(format!("{}/", server.uri())),
        )
        .expect("trace client must construct");
        let result = client
            .set_alias_enabled(AliasId(trace.alias_id), trace.desired_enabled)
            .await;

        match (trace.expected_enabled, trace.expected_error) {
            (Some(expected), None) => {
                assert_eq!(
                    result.expect("successful trace must converge").enabled,
                    expected,
                    "{}",
                    trace.name
                );
            }
            (None, Some(expected)) => {
                let error = result.expect_err("interference trace must fail safely");
                assert!(matches!(error, AliasError::ConcurrentMutation { .. }));
                assert_eq!(error.to_string(), expected, "{}", trace.name);
            }
            _ => panic!("{} has an invalid expected result", trace.name),
        }
        assert_eq!(cursor.load(Ordering::SeqCst), steps.len(), "{}", trace.name);
        assert_eq!(
            toggles.load(Ordering::SeqCst),
            trace.expected_toggle_count,
            "{}",
            trace.name
        );
        if let Some(expected) = trace.expected_enabled {
            assert_eq!(enabled.load(Ordering::SeqCst), expected, "{}", trace.name);
        }
    }
}

#[tokio::test]
async fn production_delete_refines_non_destructive_and_no_replay_semantics() {
    let vectors = vectors();
    assert_eq!(
        vectors.operation_semantics.disable.provider_resource,
        "retained"
    );
    assert_eq!(
        vectors.operation_semantics.disable.vault_cipher,
        "unchanged"
    );
    assert_eq!(
        vectors.operation_semantics.disable.success_evidence,
        "fresh-read"
    );
    assert_eq!(
        vectors.operation_semantics.delete.provider_resource,
        "removed-on-provider-confirmation"
    );
    assert_eq!(vectors.operation_semantics.delete.vault_cipher, "unchanged");
    assert_eq!(
        vectors.operation_semantics.delete.transport_failure,
        "unknown-no-automatic-replay"
    );

    let confirmed_id = vectors.operation_semantics.delete.confirmed_alias_id;
    let server = MockServer::start().await;
    Mock::given(matchers::method("DELETE"))
        .and(matchers::path(format!("/api/aliases/{confirmed_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"deleted": true})))
        .expect(1)
        .mount(&server)
        .await;
    let client = AliasClient::new(
        AliasClientSettings::new(SensitiveString::from("formal-test-token"))
            .with_base_url(format!("{}/", server.uri())),
    )
    .expect("delete client must construct");
    let vault_cipher = cipher(&vectors.reconciliation_vectors[0].ciphers[0]);
    let before = serde_json::to_value(&vault_cipher).expect("vault cipher must serialize");
    let result = client
        .delete_alias(AliasId(confirmed_id))
        .await
        .expect("confirmed delete must succeed");
    assert!(result.deleted);
    assert_eq!(
        serde_json::to_value(&vault_cipher).expect("vault cipher must serialize"),
        before,
        "provider deletion must not mutate a vault cipher"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("raw listener must bind");
    let address = listener.local_addr().expect("raw listener address");
    let raw_server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("first delete must connect");
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).expect("request must be readable");
        drop(stream);

        listener
            .set_nonblocking(true)
            .expect("listener must become nonblocking");
        let deadline = Instant::now() + Duration::from_millis(250);
        let mut requests = 1;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((_stream, _)) => requests += 1,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("unexpected listener error: {error}"),
            }
        }
        requests
    });
    let unknown_id = vectors.operation_semantics.delete.unknown_alias_id;
    let client = AliasClient::new(
        AliasClientSettings::new(SensitiveString::from("formal-test-token"))
            .with_base_url(format!("http://{address}/")),
    )
    .expect("loopback delete client must construct");
    let error = client
        .delete_alias(AliasId(unknown_id))
        .await
        .expect_err("lost delete response must be unknown");
    assert!(matches!(
        error,
        AliasError::MutationOutcomeUnknown {
            operation: "alias deletion"
        }
    ));
    assert_eq!(
        raw_server.join().expect("raw server must finish"),
        1,
        "unknown delete outcome must not be replayed"
    );
}
