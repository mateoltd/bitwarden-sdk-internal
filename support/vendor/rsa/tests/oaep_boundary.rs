//! Pinned Wycheproof controls exercise both OAEP dispatch paths with real private operations.
#![cfg(all(feature = "encoding", feature = "getrandom"))]

use digest::{Digest, FixedOutputReset};
use rsa::{oaep::DecryptingKey, pkcs8::DecodePrivateKey, traits::Decryptor, Oaep, RsaPrivateKey};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    number_of_tests: usize,
    test_groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    private_key_pkcs8: String,
    tests: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    tc_id: usize,
    msg: String,
    ct: String,
    label: String,
    result: String,
}

fn check<D: Digest + FixedOutputReset>(input: &str) {
    let vectors: Vectors = serde_json::from_str(input).unwrap();
    let mut count = 0;
    for group in vectors.test_groups {
        let key =
            RsaPrivateKey::from_pkcs8_der(&hex::decode(group.private_key_pkcs8).unwrap()).unwrap();
        for case in group.tests {
            let ct = hex::decode(&case.ct).unwrap();
            let msg = hex::decode(&case.msg).unwrap();
            let label = hex::decode(&case.label).unwrap();
            for without_crt in [false, true] {
                let mut key = key.clone();
                if without_crt {
                    key.clear_precomputed();
                }
                let generic = key.decrypt(Oaep::<D>::new_with_label(label.clone()), &ct);
                let typed = DecryptingKey::<D>::new_with_label(key, label.clone()).decrypt(&ct);
                for actual in [generic, typed] {
                    match case.result.as_str() {
                        "valid" => assert_eq!(actual.unwrap(), msg, "case {}", case.tc_id),
                        "invalid" => assert!(actual.is_err(), "case {}", case.tc_id),
                        other => panic!("unhandled vector classification {other}"),
                    }
                }
            }
            count += 1;
        }
    }
    assert_eq!(count, vectors.number_of_tests);
}

#[test]
fn pinned_wycheproof_sha1() {
    check::<sha1::Sha1>(include_str!("oaep-vectors/sha1.json"));
}

#[test]
fn pinned_wycheproof_sha256() {
    check::<sha2::Sha256>(include_str!("oaep-vectors/sha256.json"));
}
