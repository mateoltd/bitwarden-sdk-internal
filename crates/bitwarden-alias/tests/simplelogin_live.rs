//! Live contract test for a disposable SimpleLogin checkout.
//!
//! Run with:
//! `SIMPLELOGIN_API_URL=... SIMPLELOGIN_API_TOKEN=... cargo test -p bitwarden-alias --test simplelogin_live -- --ignored`

use std::time::{SystemTime, UNIX_EPOCH};

use bitwarden_alias::{
    AliasClient, AliasClientSettings, AliasId, CreateCustomAliasRequest, CreateRandomAliasRequest,
    ListAliasesRequest, SearchAliasesRequest, UpdateAliasRequest,
};
use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};

#[tokio::test]
#[ignore = "requires a disposable SimpleLogin server and API token"]
async fn complete_lifecycle_against_real_simplelogin() {
    let api_url = std::env::var("SIMPLELOGIN_API_URL")
        .expect("SIMPLELOGIN_API_URL must point at the disposable SimpleLogin checkout");
    let api_token = std::env::var("SIMPLELOGIN_API_TOKEN")
        .expect("SIMPLELOGIN_API_TOKEN must belong to the disposable SimpleLogin account");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    let hostname = SensitiveString::from(format!("sdk-{unique}.integration.test"));
    let search = SensitiveString::from(format!("sdk-live-{unique}"));

    let client = AliasClient::new(
        AliasClientSettings::new(SensitiveString::from(api_token)).with_base_url(api_url),
    )
    .expect("live SimpleLogin client should be constructible");

    let options = client
        .get_alias_options(Some(&hostname))
        .await
        .expect("real creation options should load");
    assert!(options.can_create);
    assert!(!options.suffixes.is_empty());

    let mailboxes = client
        .list_mailboxes()
        .await
        .expect("real mailboxes should load");
    let mailbox = mailboxes
        .iter()
        .find(|mailbox| mailbox.verified && mailbox.is_default)
        .or_else(|| mailboxes.iter().find(|mailbox| mailbox.verified))
        .expect("the disposable account should have a verified mailbox");

    let random = client
        .create_random_alias(CreateRandomAliasRequest {
            hostname: Some(SensitiveString::from(hostname.expose().to_owned())),
            mode: None,
            note: Some(SensitiveString::from(search.expose().to_owned())),
        })
        .await
        .expect("real random alias creation should succeed");
    let random_id = random.id;
    let random_email = random.email.expose().to_owned();
    assert!(random_id.0 > 0);

    let listed = client
        .list_aliases(ListAliasesRequest::default())
        .await
        .expect("real alias listing should succeed");
    assert!(listed.aliases.iter().any(|alias| alias.id == random_id));

    let searched = client
        .search_aliases(SearchAliasesRequest {
            query: SensitiveString::from(search.expose().to_owned()),
            page: 0,
            filter: None,
        })
        .await
        .expect("real alias search should succeed");
    assert!(searched.aliases.iter().any(|alias| alias.id == random_id));

    let detail = client
        .get_alias(random_id)
        .await
        .expect("real alias detail should succeed");
    assert_eq!(detail.id, random_id);
    assert_eq!(detail.email.expose(), random_email.as_str());

    let updated = client
        .update_alias(
            random_id,
            UpdateAliasRequest {
                note: Some(Some(SensitiveString::from(format!(
                    "updated-sdk-live-{unique}"
                )))),
                name: Some(Some(SensitiveString::from("SDK live alias"))),
                ..UpdateAliasRequest::default()
            },
        )
        .await
        .expect("real alias update should succeed");
    assert_eq!(updated.id, random_id);
    assert_eq!(
        updated
            .name
            .as_ref()
            .expect("updated name should be present")
            .expose(),
        "SDK live alias"
    );

    let disabled = client
        .disable_alias(random_id)
        .await
        .expect("real alias disable should succeed");
    assert!(!disabled.enabled);
    let enabled = client
        .enable_alias(random_id)
        .await
        .expect("real alias enable should succeed");
    assert!(enabled.enabled);

    let recommendation = client
        .get_alias_recommendation(&hostname)
        .await
        .expect("real recommendation should load")
        .expect("hostname-associated alias should be recommended");
    assert_eq!(recommendation.alias.expose(), random_email.as_str());

    let reverse_alias = client
        .create_contact(
            random_id,
            SensitiveString::from(format!("sdk-contact-{unique}@example.net")),
        )
        .await
        .expect("real reverse alias creation should succeed");
    assert!(reverse_alias.id.0 > 0);
    assert!(!reverse_alias.reverse_alias_address.expose().is_empty());

    let contacts = client
        .list_contacts(random_id, 0)
        .await
        .expect("real contact listing should succeed");
    assert!(
        contacts
            .contacts
            .iter()
            .any(|contact| contact.id == reverse_alias.id)
    );
    let blocked = client
        .toggle_contact_blocked(reverse_alias.id)
        .await
        .expect("real contact block should succeed");
    assert!(blocked.block_forward);
    client
        .delete_contact(reverse_alias.id)
        .await
        .expect("real contact deletion should succeed");

    let domains = client
        .list_domains()
        .await
        .expect("real alias domains should load");
    assert!(!domains.is_empty());
    client
        .list_custom_domains()
        .await
        .expect("real custom domains should load");

    let suffix = options
        .suffixes
        .into_iter()
        .find(|suffix| !suffix.is_premium && !suffix.is_custom)
        .expect("the disposable account should expose a public suffix");
    let custom = client
        .create_custom_alias(CreateCustomAliasRequest {
            alias_prefix: format!("sdk{unique}"),
            signed_suffix: suffix.signed_suffix,
            mailbox_ids: vec![mailbox.id],
            hostname: None,
            note: Some(SensitiveString::from("SDK live custom alias")),
            name: Some(SensitiveString::from("SDK custom")),
        })
        .await
        .expect("real custom alias creation should succeed");
    assert!(custom.id.0 > 0);
    assert_ne!(custom.id, random_id);

    delete_alias(&client, custom.id).await;
    delete_alias(&client, random_id).await;
}

async fn delete_alias(client: &AliasClient, alias_id: AliasId) {
    let deleted = client
        .delete_alias(alias_id)
        .await
        .expect("real alias cleanup should succeed");
    assert!(deleted.deleted);
}
