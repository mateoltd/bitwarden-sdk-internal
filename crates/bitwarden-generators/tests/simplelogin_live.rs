//! Live contract test for the GPL-only SimpleLogin generator bridge.
//!
//! Run with:
//! `SIMPLELOGIN_API_URL=... SIMPLELOGIN_API_TOKEN=... cargo test -p bitwarden-generators --features alias --test simplelogin_live -- --ignored`

#![cfg(feature = "alias")]

use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_alias::{AliasClient, AliasClientSettings, SearchAliasesRequest};
use bitwarden_core::Client;
use bitwarden_generators::{ForwarderServiceType, GeneratorClientsExt, UsernameGeneratorRequest};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};

#[tokio::test]
#[ignore = "requires a disposable SimpleLogin server and API token"]
async fn legacy_address_and_first_class_identity_against_real_simplelogin() {
    let api_url = std::env::var("SIMPLELOGIN_API_URL")
        .expect("SIMPLELOGIN_API_URL must point at the disposable SimpleLogin checkout");
    let api_token = std::env::var("SIMPLELOGIN_API_TOKEN")
        .expect("SIMPLELOGIN_API_TOKEN must belong to the disposable SimpleLogin account");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let legacy_hostname = format!("legacy-generator-{unique}.integration.test");
    let first_class_hostname = format!("identity-generator-{unique}.integration.test");

    let sdk = Client::new(None);
    let legacy_address = sdk
        .generator()
        .username(UsernameGeneratorRequest::Forwarded {
            service: ForwarderServiceType::SimpleLogin {
                api_key: api_token.clone(),
                base_url: api_url.clone(),
            },
            website: Some(legacy_hostname),
        })
        .await
        .expect("legacy generator should create a real alias through alias-core");

    let lifecycle = AliasClient::new(
        AliasClientSettings::new(SensitiveString::from(api_token.clone()))
            .with_base_url(api_url.clone()),
    )
    .expect("live SimpleLogin client should be constructible");
    let legacy_matches = lifecycle
        .search_aliases(SearchAliasesRequest {
            query: SensitiveString::from(legacy_address.clone()),
            page: 0,
            filter: None,
        })
        .await
        .expect("legacy-created alias should be searchable by address");
    let legacy_alias = legacy_matches
        .aliases
        .into_iter()
        .find(|alias| alias.email.expose() == &legacy_address)
        .expect("legacy-created alias should retain a provider identity in SimpleLogin");

    let first_class_alias = sdk
        .generator()
        .simplelogin_alias(
            AliasClientSettings::new(SensitiveString::from(api_token)).with_base_url(api_url),
            Some(SensitiveString::from(first_class_hostname)),
        )
        .await
        .expect("first-class generator should return real alias lifecycle data");
    let first_class_detail = lifecycle
        .get_alias(first_class_alias.id)
        .await
        .expect("first-class stable alias identity should resolve to provider detail");

    let legacy_id = legacy_alias.id;
    let first_class_id = first_class_alias.id;
    let first_class_address = first_class_alias.email.expose().to_owned();
    let first_class_detail_address = first_class_detail.email.expose().to_owned();

    lifecycle
        .delete_alias(first_class_id)
        .await
        .expect("first-class alias cleanup should succeed");
    lifecycle
        .delete_alias(legacy_id)
        .await
        .expect("legacy alias cleanup should succeed");

    assert!(legacy_id.0 > 0);
    assert!(first_class_id.0 > 0);
    assert_ne!(legacy_id, first_class_id);
    assert_eq!(first_class_address, first_class_detail_address);
}
