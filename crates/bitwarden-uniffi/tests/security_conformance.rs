//! Provider-neutral conformance checks through the exported UniFFI API surface.

use bitwarden_alias::{ALIAS_CONTRACT_VERSION, AliasError, AliasIdentity, AliasJournal};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use bitwarden_uniffi::alias::{
    canonicalize_alias_journal, create_alias_reference, merge_alias_journals,
    parse_alias_reference, serialize_alias_reference,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../formal/alias-security/conformance-vectors.json");

#[test]
fn journal_merge_rejects_conflicts_through_the_exported_api() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let vector = &vectors["journalMergeVectors"][0];
    let left: AliasJournal = serde_json::from_value(serde_json::json!({
        "version": 1,
        "connectionId": vector["connectionId"],
        "events": vector["leftEvents"],
    }))
    .unwrap();
    let mut right = left.clone();
    right.events[0].event_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3".to_owned();
    let mut changed_target = right.clone();
    changed_target.events[0].replica_id = "cccccccc-cccc-4ccc-8ccc-ccccccccccc2".to_owned();
    changed_target.events[0].target.as_mut().unwrap().alias_id = "another-resource".to_owned();

    for right in [right, changed_target] {
        canonicalize_alias_journal(left.clone()).unwrap();
        canonicalize_alias_journal(right.clone()).unwrap();
        assert!(matches!(
            merge_alias_journals(left.clone(), right.clone()),
            Err(AliasError::SyncConflict)
        ));
        assert!(matches!(
            merge_alias_journals(right, left.clone()),
            Err(AliasError::SyncConflict)
        ));
    }
}

#[test]
fn provider_neutral_reference_security_conformance() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("conformance vectors must be JSON");
    assert_eq!(
        vectors["contractVersion"].as_u64(),
        Some(u64::from(ALIAS_CONTRACT_VERSION))
    );

    for vector in vectors["referenceVectors"]
        .as_array()
        .expect("referenceVectors must be an array")
    {
        let identity_name = vector["identity"]
            .as_str()
            .expect("a reference vector must select an identity");
        let connection_id = vectors["identities"][identity_name]["connectionId"]
            .as_str()
            .expect("the selected identity must have a connection ID");
        let alias_id = vector["aliasId"]
            .as_str()
            .expect("a reference vector must have an alias ID");
        let address = vector["address"]
            .as_str()
            .expect("a reference vector must have an address");
        let canonical = vector["expectedCanonical"]
            .as_str()
            .expect("a reference vector must have canonical output");
        let identity = AliasIdentity {
            version: ALIAS_CONTRACT_VERSION,
            connection_id: connection_id.to_owned(),
            alias_id: alias_id.to_owned(),
            address: SensitiveString::from(address),
        };

        let encoded =
            create_alias_reference(identity).expect("the neutral identity vector must be valid");
        assert_eq!(encoded.expose(), canonical);

        let parsed =
            parse_alias_reference(encoded).expect("the canonical reference vector must parse");
        assert_eq!(parsed.version, ALIAS_CONTRACT_VERSION);
        assert_eq!(parsed.connection_id, connection_id);
        assert_eq!(parsed.alias_id, alias_id);
        assert_eq!(parsed.address.expose(), address);
        assert_eq!(
            serialize_alias_reference(parsed)
                .expect("the parsed reference must re-serialize")
                .expose(),
            canonical,
        );
    }

    for vector in vectors["rejectedReferenceVectors"]
        .as_array()
        .expect("rejectedReferenceVectors must be an array")
    {
        let encoded = vector["encoded"]
            .as_str()
            .expect("a rejected reference vector must have encoded input");
        let error = parse_alias_reference(SensitiveString::from(encoded))
            .expect_err("every rejected reference vector must fail closed");
        assert!(!format!("{error:?}").contains(encoded));
    }
}
