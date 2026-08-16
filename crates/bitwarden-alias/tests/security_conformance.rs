//! Executable refinement checks for the machine-checked provider-neutral alias model.

use std::{fs, path::Path};

use bitwarden_alias::{
    Alias, AliasAdapterDescriptor, AliasConsistency, AliasError, AliasFreshness, AliasIdentity,
    AliasJournal, AliasLifecycleState, AliasProviderCapabilities, AliasReconciliationError,
    AliasReferenceError, AliasTelemetryEvent, apply_alias_reconciliation, create_alias_reference,
    parse_alias_reference, plan_alias_reconciliation,
};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_vault::{
    CipherId, CipherRepromptType, CipherType, CipherView, FieldType, FieldView, LoginView,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

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
    rejected_reference_vectors: Vec<RejectedReferenceVector>,
    adapter_vectors: AdapterVectors,
    capability_vectors: CapabilityVectors,
    journal_schema: JournalSchema,
    journal_merge_vectors: Vec<JournalMergeVector>,
    reconciliation_vectors: Vec<ReconciliationVector>,
    operation_semantics: OperationSemantics,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceSchema {
    version: u32,
    login_member_name: String,
    max_encoded_bytes: usize,
    max_alias_id_bytes: usize,
    ordered_fields: Vec<String>,
    forbidden_fields: Vec<String>,
    credential_sentinel: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identities {
    primary: Connection,
    second_connection: Connection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    connection_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferenceVector {
    identity: String,
    alias_id: String,
    address: String,
    expected_canonical: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RejectedReferenceVector {
    classification: String,
    encoded: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdapterVectors {
    accepted_ids: Vec<String>,
    rejected_ids: Vec<String>,
    common_contract_must_not_contain: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityVectors {
    first_class: AliasProviderCapabilities,
    with_extension: CapabilityExtensions,
    rejected_extensions: Vec<String>,
}

#[derive(Deserialize)]
struct CapabilityExtensions {
    extensions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalSchema {
    version: u32,
    max_events: usize,
    max_causal_entries: usize,
    ordered_journal_fields: Vec<String>,
    ordered_event_fields: Vec<String>,
    forbidden_fields: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalMergeVector {
    name: String,
    connection_id: String,
    left_events: Vec<Value>,
    right_events: Vec<Value>,
    expected: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationVector {
    connection_id: String,
    aliases: Vec<AliasFixture>,
    ciphers: Vec<CipherFixture>,
    expected: ReconciliationExpected,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AliasFixture {
    alias_id: String,
    address: String,
    lifecycle: AliasLifecycleState,
    freshness: AliasFreshness,
    consistency: AliasConsistency,
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
    alias_reference: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconciliationExpected {
    proposed_repairs: u64,
    changed_cipher_ids: Vec<String>,
    unchanged_actions_on_replay: u64,
    actions_after_replan: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OperationSemantics {
    telemetry_allowlist: Vec<String>,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("canonical vectors must deserialize")
}

#[test]
fn formal_model_digest_and_schema_constants_match() {
    let vectors = vectors();
    assert_eq!(vectors.contract_version, 1);
    assert_eq!(vectors.model_revision, "alias-security-v1-provider-neutral");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut digest = Sha256::new();
    for file in &vectors.model_files {
        digest.update(
            fs::read(root.join("formal/alias-security").join(file))
                .expect("declared model file must exist"),
        );
    }
    let actual = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(actual, vectors.model_sha256);
    assert_eq!(vectors.reference_schema.version, 1);
    assert_eq!(vectors.reference_schema.login_member_name, "aliasReference");
    assert_eq!(vectors.reference_schema.max_encoded_bytes, 4096);
    assert_eq!(vectors.reference_schema.max_alias_id_bytes, 512);
    assert_eq!(
        vectors.reference_schema.ordered_fields,
        ["version", "connectionId", "aliasId", "address"]
    );
    assert_eq!(vectors.journal_schema.version, 1);
    assert_eq!(vectors.journal_schema.max_events, 10_000);
    assert_eq!(vectors.journal_schema.max_causal_entries, 128);
    assert_eq!(
        vectors.journal_schema.ordered_journal_fields,
        ["version", "connectionId", "events"]
    );
    assert_eq!(vectors.journal_schema.ordered_event_fields.len(), 11);
}

#[test]
fn reference_vectors_are_exact_connection_scoped_and_opaque() {
    let vectors = vectors();
    for vector in vectors.reference_vectors {
        let connection_id = match vector.identity.as_str() {
            "primary" => &vectors.identities.primary.connection_id,
            "secondConnection" => &vectors.identities.second_connection.connection_id,
            other => panic!("unknown identity fixture {other}"),
        };
        let identity = AliasIdentity::new(
            connection_id.clone(),
            vector.alias_id.clone(),
            SensitiveString::from(vector.address),
        )
        .expect("accepted identity should validate");
        let encoded = create_alias_reference(&identity).expect("reference should encode");
        assert_eq!(encoded.expose(), &vector.expected_canonical);
        let parsed = parse_alias_reference(encoded.expose()).expect("reference should parse");
        assert_eq!(parsed.alias_id, vector.alias_id);
        assert_eq!(parsed.connection_id, *connection_id);
    }
}

#[test]
fn alias_addresses_reject_internal_whitespace() {
    assert!(
        AliasIdentity::new(
            vectors().identities.primary.connection_id,
            "opaque/id:%2F7".to_owned(),
            SensitiveString::from("first user@example.test"),
        )
        .is_err()
    );
}

#[test]
fn old_or_malformed_reference_shapes_fail_closed() {
    for vector in vectors().rejected_reference_vectors {
        let error = parse_alias_reference(&vector.encoded).expect_err("vector must be rejected");
        match vector.classification.as_str() {
            "malformed" => assert!(matches!(error, AliasReferenceError::Malformed)),
            "unsupportedVersion" => {
                assert!(matches!(error, AliasReferenceError::UnsupportedVersion))
            }
            "invalidValue" => assert!(matches!(error, AliasReferenceError::InvalidValue)),
            other => panic!("unknown rejection class {other}"),
        }
    }
}

#[test]
fn adapter_and_capability_identifiers_are_extensible_not_enums() {
    let vectors = vectors();
    for adapter_id in vectors.adapter_vectors.accepted_ids {
        AliasAdapterDescriptor {
            adapter_id,
            capabilities: vectors.capability_vectors.first_class.clone(),
        }
        .canonicalize()
        .expect("accepted adapter ID should validate");
    }
    for adapter_id in vectors.adapter_vectors.rejected_ids {
        assert!(matches!(
            AliasAdapterDescriptor {
                adapter_id,
                capabilities: vectors.capability_vectors.first_class.clone(),
            }
            .canonicalize(),
            Err(AliasError::InvalidInput)
        ));
    }
    let mut extended = vectors.capability_vectors.first_class.clone();
    extended.extensions = vectors.capability_vectors.with_extension.extensions;
    AliasAdapterDescriptor {
        adapter_id: "example.alias-v2".to_owned(),
        capabilities: extended,
    }
    .canonicalize()
    .expect("validated extensions remain open-ended");
    for extension in vectors.capability_vectors.rejected_extensions {
        let mut capabilities = vectors.capability_vectors.first_class.clone();
        capabilities.extensions = vec![extension];
        assert!(
            AliasAdapterDescriptor {
                adapter_id: "example".to_owned(),
                capabilities,
            }
            .canonicalize()
            .is_err()
        );
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let common = ["models.rs", "journal.rs", "reconciliation.rs", "error.rs"]
        .into_iter()
        .map(|file| fs::read_to_string(root.join(file)).unwrap())
        .collect::<String>();
    for named_provider in vectors.adapter_vectors.common_contract_must_not_contain {
        assert!(!common.contains(&named_provider));
    }
}

#[test]
fn journal_vectors_refine_unknown_tombstone_and_conflict_semantics() {
    for vector in vectors().journal_merge_vectors {
        let journal = |events: Vec<Value>| {
            serde_json::from_value::<AliasJournal>(serde_json::json!({
                "version": 1,
                "connectionId": vector.connection_id,
                "events": events,
            }))
            .expect("journal vector should deserialize")
        };
        let left = journal(vector.left_events);
        let right = journal(vector.right_events);
        let merged = left.merge(&right).expect("journal merge should succeed");
        assert_eq!(merged, right.merge(&left).unwrap(), "merge is commutative");
        assert_eq!(
            merged,
            merged.merge(&merged).unwrap(),
            "merge is idempotent"
        );
        let empty = AliasJournal::empty(vector.connection_id.clone()).unwrap();
        assert_eq!(
            left.merge(&right).unwrap().merge(&empty).unwrap(),
            left.merge(&right.merge(&empty).unwrap()).unwrap(),
            "merge is associative"
        );
        let reduced = merged.reduce().expect("merged journal should reduce");
        match vector.name.as_str() {
            "dispatched-delete-with-lost-response-remains-unknown" => {
                assert_eq!(
                    merged.events.len() as u64,
                    vector.expected["mergedEventCount"].as_u64().unwrap()
                );
                assert_eq!(
                    serde_json::to_value(reduced.operations[0].phase).unwrap(),
                    vector.expected["phase"]
                );
            }
            "delete-tombstone-dominates-stale-enabled-observation" => {
                assert_eq!(reduced.resources[0].lifecycle, AliasLifecycleState::Deleted);
                assert!(reduced.resources[0].tombstoned);
            }
            "concurrent-incompatible-lifecycle-observations-conflict" => {
                assert!(!reduced.conflicts.is_empty());
            }
            other => panic!("unknown journal vector {other}"),
        }
        assert_eq!(format!("{merged:?}"), "AliasJournal([REDACTED])");
    }
}

#[test]
fn reconciliation_is_atomic_idempotent_and_frame_preserving() {
    for vector in vectors().reconciliation_vectors {
        let capabilities = AliasProviderCapabilities::first_class();
        let aliases = vector
            .aliases
            .into_iter()
            .map(|alias| Alias {
                identity: AliasIdentity::new(
                    vector.connection_id.clone(),
                    alias.alias_id,
                    SensitiveString::from(alias.address),
                )
                .unwrap(),
                lifecycle: alias.lifecycle,
                freshness: alias.freshness,
                consistency: alias.consistency,
                label: None,
                capabilities: capabilities.clone(),
            })
            .collect::<Vec<_>>();
        let mut ciphers = vector
            .ciphers
            .into_iter()
            .map(cipher_from_fixture)
            .collect::<Vec<_>>();
        let unrelated_before = serde_json::to_value(&ciphers[1]).unwrap();
        let target_fields_before = serde_json::to_value(&ciphers[0].fields).unwrap();
        let target_password_before = ciphers[0].login.as_ref().unwrap().password.clone();

        let plan = plan_alias_reconciliation(&vector.connection_id, &aliases, &ciphers).unwrap();
        assert_eq!(
            plan.summary.proposed_repairs,
            vector.expected.proposed_repairs
        );
        let first = apply_alias_reconciliation(&plan, &aliases, &mut ciphers).unwrap();
        assert_eq!(
            first
                .changed_cipher_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vector.expected.changed_cipher_ids
        );
        assert_eq!(serde_json::to_value(&ciphers[1]).unwrap(), unrelated_before);
        assert_eq!(
            serde_json::to_value(&ciphers[0].fields).unwrap(),
            target_fields_before
        );
        assert_eq!(
            ciphers[0].login.as_ref().unwrap().password,
            target_password_before
        );
        let replay = apply_alias_reconciliation(&plan, &aliases, &mut ciphers).unwrap();
        assert_eq!(
            replay.unchanged_actions,
            vector.expected.unchanged_actions_on_replay
        );
        let replanned =
            plan_alias_reconciliation(&vector.connection_id, &aliases, &ciphers).unwrap();
        assert_eq!(
            replanned.actions.len(),
            vector.expected.actions_after_replan
        );
    }
}

#[test]
fn reconciliation_never_repairs_from_stale_or_conflicted_provider_state() {
    let identity = AliasIdentity::new(
        "11111111-1111-4111-8111-111111111111".to_owned(),
        "opaque/id:%2F7".to_owned(),
        SensitiveString::from("first@example.test"),
    )
    .unwrap();
    for (freshness, consistency) in [
        (AliasFreshness::Stale, AliasConsistency::Clean),
        (AliasFreshness::Current, AliasConsistency::Conflicted),
    ] {
        let alias = Alias {
            identity: identity.clone(),
            lifecycle: AliasLifecycleState::Enabled,
            freshness,
            consistency,
            label: None,
            capabilities: AliasProviderCapabilities::first_class(),
        };
        assert!(matches!(
            plan_alias_reconciliation(&identity.connection_id, &[alias], &[]),
            Err(AliasReconciliationError::InvalidInput)
        ));
    }
}

#[test]
fn closed_schemas_and_telemetry_exclude_sensitive_fields() {
    let vectors = vectors();
    for forbidden in vectors
        .reference_schema
        .forbidden_fields
        .iter()
        .chain(&vectors.journal_schema.forbidden_fields)
    {
        assert!(!vectors.reference_schema.ordered_fields.contains(forbidden));
        assert!(
            !vectors
                .journal_schema
                .ordered_event_fields
                .contains(forbidden)
        );
    }
    assert!(!VECTORS.contains(&format!(
        "\"{}\":",
        vectors.reference_schema.credential_sentinel
    )));
    let telemetry = AliasTelemetryEvent {
        operation: bitwarden_alias::AliasOperationKind::Reconcile,
        platform: bitwarden_alias::AliasPlatform::Other,
        error_code: None,
        success: true,
    };
    let mut fields = serde_json::to_value(telemetry)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut expected = vectors.operation_semantics.telemetry_allowlist;
    fields.sort();
    expected.sort();
    assert_eq!(fields, expected);

    assert!(
        serde_json::from_value::<bitwarden_alias::AliasReconciliationOutcome>(serde_json::json!({
            "status": "unboundAlias",
            "aliasId": "remote/object:7",
            "providerBody": "forbidden"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<bitwarden_alias::AliasReconciliationAction>(serde_json::json!({
            "action": "refresh",
            "aliasId": "remote/object:7",
            "cipherId": "00000000-0000-4000-8000-000000000001",
            "referenceAddressStale": true,
            "usernameStale": true,
            "credential": "forbidden"
        }))
        .is_err()
    );
}

fn cipher_from_fixture(fixture: CipherFixture) -> CipherView {
    let timestamp = "2026-08-10T10:00:00Z"
        .parse()
        .expect("the fixed fixture timestamp must be valid RFC 3339");
    let id: CipherId = serde_json::from_str(&format!("\"{}\"", fixture.id))
        .expect("the conformance fixture cipher ID must be a valid UUID");
    CipherView {
        id: Some(id),
        organization_id: None,
        folder_id: None,
        collection_ids: Vec::new(),
        key: None,
        name: fixture.name,
        notes: Some(fixture.notes),
        r#type: CipherType::Login,
        login: Some(LoginView {
            username: Some(fixture.username),
            password: Some("frame-preserved-password".to_owned()),
            alias_reference: fixture.alias_reference,
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
        fields: Some(vec![FieldView {
            name: Some(fixture.custom_field_name),
            value: Some(fixture.custom_field_value),
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
