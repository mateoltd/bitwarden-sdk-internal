use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use crate::{
    AliasClient, AliasClientSettings, AliasError, AliasFilter, AliasId, ContactId,
    CreateCustomAliasRequest, CreateRandomAliasRequest, CustomDomainId, ListAliasesRequest,
    MailboxId, RandomAliasMode, SearchAliasesRequest, UpdateAliasRequest,
    UpdateCustomDomainRequest,
};

const TOKEN: &str = "test-api-token";

fn client(server: &MockServer) -> AliasClient {
    AliasClient::new(
        AliasClientSettings::new(SensitiveString::from(TOKEN))
            .with_base_url(format!("{}/", server.uri())),
    )
    .expect("wiremock URL should be a valid provider URL")
}

fn alias_json(id: u64, enabled: bool) -> Value {
    json!({
        "id": id,
        "email": format!("alias-{id}@sl.test"),
        "creation_date": "2026-08-10T10:00:00+00:00",
        "creation_timestamp": 1786356000,
        "enabled": enabled,
        "note": "private note",
        "name": "Alias name",
        "nb_forward": 4,
        "nb_block": 2,
        "nb_reply": 1,
        "mailbox": {"id": 11, "email": "owner@example.test"},
        "mailboxes": [
            {"id": 11, "email": "owner@example.test"},
            {"id": 12, "email": "backup@example.test"}
        ],
        "support_pgp": true,
        "disable_pgp": false,
        "latest_activity": {
            "timestamp": 1786357000,
            "action": "forward",
            "contact": {
                "email": "sender@example.test",
                "name": "Sender",
                "reverse_alias": "Sender <reverse@sl.test>"
            }
        },
        "pinned": true
    })
}

fn reverse_alias_json(id: u64) -> Value {
    json!({
        "id": id,
        "creation_date": "2026-08-10T10:00:00+00:00",
        "creation_timestamp": 1786356000,
        "last_email_sent_date": null,
        "last_email_sent_timestamp": null,
        "contact": "contact@example.test",
        "reverse_alias": "Contact <reverse@sl.test>",
        "reverse_alias_address": "reverse@sl.test",
        "existed": false,
        "block_forward": false
    })
}

#[tokio::test]
async fn creates_random_and_custom_aliases_with_sensitive_authentication() {
    let server = MockServer::start().await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/alias/random/new"))
        .and(matchers::query_param("hostname", "private.example"))
        .and(matchers::query_param("mode", "word"))
        .and(matchers::header("Authentication", TOKEN))
        .and(matchers::body_json(json!({"note": "random note"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(alias_json(41, true)))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/v3/alias/custom/new"))
        .and(matchers::query_param("hostname", "private.example"))
        .and(matchers::header("Authentication", TOKEN))
        .and(matchers::body_json(json!({
            "alias_prefix": "checkout",
            "signed_suffix": ".words@sl.test.signature",
            "mailbox_ids": [11, 12],
            "note": "custom note",
            "name": "Checkout"
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(alias_json(42, true)))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let random = client
        .create_random_alias(CreateRandomAliasRequest {
            hostname: Some(SensitiveString::from("private.example")),
            mode: Some(RandomAliasMode::Word),
            note: Some(SensitiveString::from("random note")),
        })
        .await
        .expect("random alias creation should succeed");
    assert_eq!(random.id, AliasId(41));
    assert_eq!(random.email.expose(), "alias-41@sl.test");

    let custom = client
        .create_custom_alias(CreateCustomAliasRequest {
            alias_prefix: "checkout".to_owned(),
            signed_suffix: SensitiveString::from(".words@sl.test.signature"),
            mailbox_ids: vec![MailboxId(11), MailboxId(12)],
            hostname: Some(SensitiveString::from("private.example")),
            note: Some(SensitiveString::from("custom note")),
            name: Some(SensitiveString::from("Checkout")),
        })
        .await
        .expect("custom alias creation should succeed");
    assert_eq!(custom.id, AliasId(42));
    assert_eq!(custom.mailboxes.len(), 2);
}

#[tokio::test]
async fn lists_searches_and_reads_aliases_without_losing_identity() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/aliases"))
        .and(matchers::query_param("page_id", "2"))
        .and(matchers::query_param("enabled", "true"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"aliases": [alias_json(50, true)]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/v2/aliases"))
        .and(matchers::query_param("page_id", "3"))
        .and(matchers::query_param("pinned", "true"))
        .and(matchers::body_json(json!({"query": "private search"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"aliases": [alias_json(51, true)]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/52"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(52, false)))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let listed = client
        .list_aliases(ListAliasesRequest {
            page: 2,
            filter: Some(AliasFilter::Enabled),
        })
        .await
        .expect("listing should succeed");
    assert_eq!(listed.page, 2);
    assert_eq!(listed.aliases[0].id, AliasId(50));

    let searched = client
        .search_aliases(SearchAliasesRequest {
            query: SensitiveString::from("private search"),
            page: 3,
            filter: Some(AliasFilter::Pinned),
        })
        .await
        .expect("search should succeed");
    assert_eq!(searched.aliases[0].id, AliasId(51));

    let detail = client
        .get_alias(AliasId(52))
        .await
        .expect("detail should succeed");
    assert_eq!(detail.id, AliasId(52));
    assert!(!detail.enabled);
    assert_eq!(detail.latest_activity.expect("activity").action, "forward");
}

#[tokio::test]
async fn updates_sets_state_and_deletes_by_stable_id() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("PATCH"))
        .and(matchers::path("/api/aliases/60"))
        .and(matchers::body_json(json!({
            "note": null,
            "name": "Updated",
            "mailbox_ids": [12],
            "disable_pgp": true,
            "pinned": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/60"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(60, false)))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/61"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(61, true)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/61/toggle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"enabled": false})))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/62"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(62, true)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/62/toggle"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    Mock::given(matchers::method("DELETE"))
        .and(matchers::path("/api/aliases/63"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"deleted": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let updated = client
        .update_alias(
            AliasId(60),
            UpdateAliasRequest {
                note: Some(None),
                name: Some(Some(SensitiveString::from("Updated"))),
                mailbox_ids: Some(vec![MailboxId(12)]),
                disable_pgp: Some(true),
                pinned: Some(false),
            },
        )
        .await
        .expect("update should succeed");
    assert_eq!(updated.id, AliasId(60));

    let disabled = client
        .disable_alias(AliasId(61))
        .await
        .expect("disable should succeed");
    assert_eq!(disabled.id, AliasId(61));
    assert!(!disabled.enabled);

    let unchanged = client
        .enable_alias(AliasId(62))
        .await
        .expect("idempotent enable should succeed");
    assert_eq!(unchanged.id, AliasId(62));
    assert!(unchanged.enabled);

    let deleted = client
        .delete_alias(AliasId(63))
        .await
        .expect("delete should succeed");
    assert_eq!(deleted.id, AliasId(63));
    assert!(deleted.deleted);
}

#[tokio::test]
async fn supports_options_domains_and_mailboxes() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v5/alias/options"))
        .and(matchers::query_param("hostname", "shop.example"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "can_create": true,
            "suffixes": [{
                "suffix": ".words@sl.test",
                "signed_suffix": ".words@sl.test.signature",
                "is_custom": false,
                "is_premium": false
            }],
            "prefix_suggestion": "shop",
            "recommendation": {"alias": "existing@sl.test", "hostname": "shop.example"}
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/setting/domains"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"domain": "sl.test", "is_custom": false},
            {"domain": "private.test", "is_custom": true}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/mailboxes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "mailboxes": [{
                "id": 11,
                "email": "owner@example.test",
                "verified": true,
                "default": true,
                "creation_timestamp": 1786356000,
                "nb_alias": 3
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let hostname = SensitiveString::from("shop.example");
    let options = client
        .get_alias_options(Some(&hostname))
        .await
        .expect("options should succeed");
    assert!(options.can_create);
    assert_eq!(options.suffixes.len(), 1);
    assert_eq!(options.suffixes[0].signed_suffix.to_string(), "[REDACTED]");

    let recommendation = client
        .get_alias_recommendation(&hostname)
        .await
        .expect("recommendation should succeed")
        .expect("recommendation should be present");
    assert_eq!(recommendation.alias.expose(), "existing@sl.test");

    let domains = client.list_domains().await.expect("domains should succeed");
    assert_eq!(domains.len(), 2);
    assert_eq!(domains[1].domain.expose(), "private.test");

    let mailboxes = client
        .list_mailboxes()
        .await
        .expect("mailboxes should succeed");
    assert_eq!(mailboxes[0].id, MailboxId(11));
    assert!(mailboxes[0].is_default);
    assert!(mailboxes[0].creation_date.is_none());
}

#[tokio::test]
async fn supports_custom_domains_and_reverse_alias_contacts() {
    let server = MockServer::start().await;
    let domain = json!({
        "id": 71,
        "domain_name": "private.test",
        "is_verified": true,
        "nb_alias": 2,
        "creation_date": "2026-08-10T10:00:00+00:00",
        "creation_timestamp": 1786356000,
        "catch_all": false,
        "name": null,
        "random_prefix_generation": false,
        "mailboxes": [{"id": 11, "email": "owner@example.test"}]
    });
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/custom_domains"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"custom_domains": [domain.clone()]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("PATCH"))
        .and(matchers::path("/api/custom_domains/71"))
        .and(matchers::body_json(json!({
            "catch_all": true,
            "name": "Private",
            "mailbox_ids": [11]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"custom_domain": domain})))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/72/contacts"))
        .and(matchers::query_param("page_id", "4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contacts": [reverse_alias_json(73)]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/72/contacts"))
        .and(matchers::body_json(
            json!({"contact": "contact@example.test"}),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(reverse_alias_json(74)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/contacts/74/toggle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"block_forward": true})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("DELETE"))
        .and(matchers::path("/api/contacts/74"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"deleted": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let domains = client
        .list_custom_domains()
        .await
        .expect("custom domains should succeed");
    assert_eq!(domains[0].id, CustomDomainId(71));

    let updated = client
        .update_custom_domain(
            CustomDomainId(71),
            UpdateCustomDomainRequest {
                catch_all: Some(true),
                random_prefix_generation: None,
                name: Some(Some(SensitiveString::from("Private"))),
                mailbox_ids: Some(vec![MailboxId(11)]),
            },
        )
        .await
        .expect("custom domain update should succeed");
    assert_eq!(updated.id, CustomDomainId(71));

    let page = client
        .list_contacts(AliasId(72), 4)
        .await
        .expect("contacts should succeed");
    assert_eq!(page.alias_id, AliasId(72));
    assert_eq!(page.contacts[0].id, ContactId(73));
    assert_eq!(
        page.contacts[0].reverse_alias_address.expose(),
        "reverse@sl.test"
    );

    let reverse = client
        .create_contact(AliasId(72), SensitiveString::from("contact@example.test"))
        .await
        .expect("contact creation should succeed");
    assert_eq!(reverse.id, ContactId(74));

    let state = client
        .toggle_contact_blocked(ContactId(74))
        .await
        .expect("contact toggle should succeed");
    assert!(state.block_forward);

    let deleted = client
        .delete_contact(ContactId(74))
        .await
        .expect("contact deletion should succeed");
    assert!(deleted.deleted);
}

#[tokio::test]
async fn rejects_authenticated_redirects_without_contacting_destination() {
    let source = MockServer::start().await;
    let destination = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/setting/domains"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/capture", destination.uri())),
        )
        .expect(1)
        .mount(&source)
        .await;

    let error = client(&source)
        .list_domains()
        .await
        .expect_err("redirect must be rejected");
    assert!(matches!(
        error,
        AliasError::RedirectRejected { status: 302 }
    ));
    let destination_requests = destination
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert!(destination_requests.is_empty());
}

#[tokio::test]
async fn bounds_responses_and_sanitizes_rendered_errors() {
    let oversized = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/setting/domains"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_bytes(vec![b'x'; 512 * 1024 + 1]),
        )
        .mount(&oversized)
        .await;
    let error = client(&oversized)
        .list_domains()
        .await
        .expect_err("oversized response must fail");
    assert!(matches!(
        error,
        AliasError::ResponseTooLarge {
            limit_bytes: 524_288
        }
    ));

    let hostile = MockServer::start().await;
    let hostile_message =
        format!("failure {TOKEN}\n<script>alert(1)</script>\u{1b}[31m\u{202e}spoof");
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/setting/domains"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": hostile_message})))
        .mount(&hostile)
        .await;
    let error = client(&hostile)
        .list_domains()
        .await
        .expect_err("provider error must fail");
    let rendered = error.to_string();
    assert!(!rendered.contains(TOKEN));
    assert!(!rendered.contains('<'));
    assert!(!rendered.contains('>'));
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("[REDACTED]"));
    assert!(rendered.contains("[script]alert(1)[/script]"));
}

#[tokio::test]
async fn maps_auth_rate_limit_content_type_and_invalid_json_errors() {
    let unauthorized = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/setting/domains"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": TOKEN})))
        .mount(&unauthorized)
        .await;
    assert!(matches!(
        client(&unauthorized)
            .list_domains()
            .await
            .expect_err("401 should fail"),
        AliasError::AuthenticationFailed
    ));

    let rate_limited = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/setting/domains"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "17")
                .set_body_json(json!({"error": "slow down"})),
        )
        .mount(&rate_limited)
        .await;
    assert!(matches!(
        client(&rate_limited)
            .list_domains()
            .await
            .expect_err("429 should fail"),
        AliasError::RateLimited {
            retry_after_seconds: Some(17)
        }
    ));

    let html = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/setting/domains"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("<html></html>", "text/html"))
        .mount(&html)
        .await;
    assert!(matches!(
        client(&html)
            .list_domains()
            .await
            .expect_err("HTML should fail"),
        AliasError::UnexpectedContentType
    ));

    let malformed = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/setting/domains"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("{", "application/json"))
        .mount(&malformed)
        .await;
    assert!(matches!(
        client(&malformed)
            .list_domains()
            .await
            .expect_err("malformed JSON should fail"),
        AliasError::InvalidResponse(_)
    ));
}

#[test]
fn settings_and_sensitive_models_redact_secrets() {
    let settings = AliasClientSettings::new(SensitiveString::from(TOKEN));
    let rendered = format!("{settings:?}");
    assert!(!rendered.contains(TOKEN));
    assert!(rendered.contains("[REDACTED]"));

    assert!(matches!(
        AliasClient::new(
            AliasClientSettings::new(SensitiveString::from(TOKEN))
                .with_base_url("https://user:password@example.test".to_owned())
        ),
        Err(AliasError::InvalidBaseUrl(_))
    ));
    assert!(matches!(
        AliasClient::new(
            AliasClientSettings::new(SensitiveString::from("bad\ntoken"))
                .with_base_url("https://example.test".to_owned())
        ),
        Err(AliasError::InvalidAuthenticationToken)
    ));
    assert!(matches!(
        AliasClient::new(
            AliasClientSettings::new(SensitiveString::from(""))
                .with_base_url("https://example.test".to_owned())
        ),
        Err(AliasError::InvalidAuthenticationToken)
    ));
}
