use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use bitwarden_sensitive_value::{ExposeSensitive, SensitiveString};
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use crate::{
    simplelogin::{SimpleLoginAdapterSettings, SimpleLoginTransport},
    simplelogin_error::SimpleLoginError as AliasError,
    simplelogin_models::{
        AliasFilter, AliasId, ContactId, CreateRandomAliasRequest, ListAliasesRequest,
        RandomAliasMode,
    },
};

const TOKEN: &str = "test-api-token";
const CONNECTION_ID: &str = "11111111-1111-4111-8111-111111111111";

fn client(server: &MockServer) -> SimpleLoginTransport {
    SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
        CONNECTION_ID.to_owned(),
        format!("{}/", server.uri()),
        SensitiveString::from(TOKEN),
    ))
    .expect("wiremock URL should be a valid provider URL")
}

fn provider_client(server: &MockServer) -> crate::AliasClient {
    crate::SimpleLoginAdapter::new(SimpleLoginAdapterSettings::new(
        CONNECTION_ID.to_owned(),
        format!("{}/", server.uri()),
        SensitiveString::from(TOKEN),
    ))
    .expect("wiremock URL should be a valid provider URL")
    .into_client()
    .expect("provider adapter should have a valid descriptor")
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
async fn provider_neutral_adapter_rejects_nonadvancing_pagination() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/aliases"))
        .and(matchers::query_param("page_id", u32::MAX.to_string()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"aliases": [alias_json(40, true)]})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let error = provider_client(&server)
        .list(crate::ListAliasesRequest {
            page_token: Some(u32::MAX.to_string()),
        })
        .await
        .expect_err("a non-advancing provider page must fail closed");
    assert!(matches!(error, crate::AliasError::InvalidResponse));
}

#[tokio::test]
async fn provider_neutral_adapter_maps_pinned_missing_detail_to_not_found() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/40"))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;

    let identity = crate::AliasIdentity::new(
        CONNECTION_ID.to_owned(),
        "40".to_owned(),
        SensitiveString::from("alias-40@sl.test"),
    )
    .expect("identity should be valid");
    let error = provider_client(&server)
        .get(identity)
        .await
        .expect_err("the pinned provider's missing-detail response must map to not found");
    assert!(matches!(error, crate::AliasError::NotFound));
}

#[tokio::test]
async fn provider_neutral_mutations_validate_fresh_provider_snapshots() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/40"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(40, true)))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/40/contacts"))
        .and(matchers::query_param("page_id", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contacts": [reverse_alias_json(41)]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let alias = crate::AliasIdentity::new(
        CONNECTION_ID.to_owned(),
        "40".to_owned(),
        SensitiveString::from("stale-alias@sl.test"),
    )
    .expect("identity should be valid");
    let alias_error = provider_client(&server)
        .set_enabled(alias.clone(), true)
        .await
        .expect_err("a changed provider alias address must not be hidden by the adapter");
    assert!(matches!(alias_error, crate::AliasError::InvalidResponse));

    let contact = crate::SendReplyIdentity {
        alias,
        identity_id: "41".to_owned(),
        recipient: SensitiveString::from("stale-contact@example.test"),
        address: SensitiveString::from("stale-reverse@sl.test"),
        valid: true,
        blocked: Some(false),
    };
    let contact_error = provider_client(&server)
        .set_send_reply_blocked(contact, false)
        .await
        .expect_err("changed provider contact identity must not be hidden by the adapter");
    assert!(matches!(contact_error, crate::AliasError::InvalidResponse));
}

#[tokio::test]
async fn creates_random_aliases_with_sensitive_authentication() {
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
}

#[tokio::test]
async fn lists_and_reads_aliases_without_losing_identity() {
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

    let detail = client
        .get_alias(AliasId(52))
        .await
        .expect("detail should succeed");
    assert_eq!(detail.id, AliasId(52));
    assert!(!detail.enabled);
    assert_eq!(detail.latest_activity.expect("activity").action, "forward");
}

#[tokio::test]
async fn sets_state_and_deletes_by_stable_id() {
    let server = MockServer::start().await;
    let alias_61_enabled = Arc::new(AtomicBool::new(true));
    let state = Arc::clone(&alias_61_enabled);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/61"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(alias_json(61, state.load(Ordering::SeqCst)))
        })
        .expect(2)
        .mount(&server)
        .await;
    let state = Arc::clone(&alias_61_enabled);
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/61/toggle"))
        .respond_with(move |_: &wiremock::Request| {
            state.store(false, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({"enabled": false}))
        })
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
    let disabled = client
        .set_alias_enabled(AliasId(61), false)
        .await
        .expect("disable should succeed");
    assert_eq!(disabled.id, AliasId(61));
    assert!(!disabled.enabled);

    let unchanged = client
        .set_alias_enabled(AliasId(62), true)
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
async fn supports_reverse_alias_contacts() {
    let server = MockServer::start().await;
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
    Mock::given(matchers::method("DELETE"))
        .and(matchers::path("/api/contacts/74"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"deleted": true})))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let page = client
        .list_reverse_aliases(AliasId(72), 4)
        .await
        .expect("contacts should succeed");
    assert_eq!(page.alias_id, AliasId(72));
    assert_eq!(page.contacts[0].id, ContactId(73));
    assert_eq!(
        page.contacts[0].reverse_alias_address.expose(),
        "reverse@sl.test"
    );

    let reverse = client
        .create_reverse_alias(AliasId(72), SensitiveString::from("contact@example.test"))
        .await
        .expect("contact creation should succeed");
    assert_eq!(reverse.id, ContactId(74));

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
        .and(matchers::path("/api/v2/aliases"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/capture", destination.uri())),
        )
        .expect(1)
        .mount(&source)
        .await;

    let error = client(&source)
        .list_aliases(ListAliasesRequest::default())
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
async fn bounds_responses_and_never_renders_provider_controlled_errors() {
    let oversized = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/aliases"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_bytes(vec![b'x'; 512 * 1024 + 1]),
        )
        .mount(&oversized)
        .await;
    let error = client(&oversized)
        .list_aliases(ListAliasesRequest::default())
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
        .and(matchers::path("/api/v2/aliases"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": hostile_message})))
        .mount(&hostile)
        .await;
    let error = client(&hostile)
        .list_aliases(ListAliasesRequest::default())
        .await
        .expect_err("provider error must fail");
    let rendered = error.to_string();
    assert!(!rendered.contains(TOKEN));
    assert!(!rendered.contains('<'));
    assert!(!rendered.contains('>'));
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains("alert(1)"));
    assert_eq!(rendered, "alias provider request failed (HTTP 400)");
}

#[tokio::test]
async fn maps_auth_rate_limit_content_type_and_invalid_json_errors() {
    let unauthorized = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/aliases"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"error": TOKEN})))
        .mount(&unauthorized)
        .await;
    assert!(matches!(
        client(&unauthorized)
            .list_aliases(ListAliasesRequest::default())
            .await
            .expect_err("401 should fail"),
        AliasError::AuthenticationFailed
    ));

    let rate_limited = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/aliases"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "17")
                .set_body_json(json!({"error": "slow down"})),
        )
        .mount(&rate_limited)
        .await;
    assert!(matches!(
        client(&rate_limited)
            .list_aliases(ListAliasesRequest::default())
            .await
            .expect_err("429 should fail"),
        AliasError::RateLimited {
            retry_after_seconds: Some(17)
        }
    ));

    let html = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/aliases"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("<html></html>", "text/html"))
        .mount(&html)
        .await;
    assert!(matches!(
        client(&html)
            .list_aliases(ListAliasesRequest::default())
            .await
            .expect_err("HTML should fail"),
        AliasError::UnexpectedContentType
    ));

    let malformed = MockServer::start().await;
    Mock::given(matchers::path("/api/v2/aliases"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("{", "application/json"))
        .mount(&malformed)
        .await;
    assert!(matches!(
        client(&malformed)
            .list_aliases(ListAliasesRequest::default())
            .await
            .expect_err("malformed JSON should fail"),
        AliasError::InvalidResponse(_)
    ));
}

#[tokio::test]
async fn serializes_concurrent_explicit_state_changes() {
    let server = MockServer::start().await;
    let enabled = Arc::new(AtomicBool::new(true));
    let toggle_count = Arc::new(AtomicUsize::new(0));

    let state = Arc::clone(&enabled);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/91"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(50))
                .set_body_json(alias_json(91, state.load(Ordering::SeqCst)))
        })
        .expect(3)
        .mount(&server)
        .await;

    let state = Arc::clone(&enabled);
    let requests = Arc::clone(&toggle_count);
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/91/toggle"))
        .respond_with(move |_: &wiremock::Request| {
            requests.fetch_add(1, Ordering::SeqCst);
            let new_state = !state.fetch_xor(true, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({"enabled": new_state}))
        })
        .expect(1)
        .mount(&server)
        .await;

    let first_client = client(&server);
    let second_client = client(&server);
    let (first, second) = tokio::join!(
        first_client.set_alias_enabled(AliasId(91), false),
        second_client.set_alias_enabled(AliasId(91), false)
    );
    assert!(!first.expect("first disable should succeed").enabled);
    assert!(!second.expect("second disable should be idempotent").enabled);
    assert!(!enabled.load(Ordering::SeqCst));
    assert_eq!(toggle_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn serializes_concurrent_explicit_contact_state_changes() {
    let server = MockServer::start().await;
    let blocked = Arc::new(AtomicBool::new(false));
    let toggle_count = Arc::new(AtomicUsize::new(0));

    let state = Arc::clone(&blocked);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/91/contacts"))
        .respond_with(move |_: &wiremock::Request| {
            let mut contact = reverse_alias_json(74);
            contact["block_forward"] = json!(state.load(Ordering::SeqCst));
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(50))
                .set_body_json(json!({"contacts": [contact]}))
        })
        .expect(3)
        .mount(&server)
        .await;

    let state = Arc::clone(&blocked);
    let requests = Arc::clone(&toggle_count);
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/contacts/74/toggle"))
        .respond_with(move |_: &wiremock::Request| {
            requests.fetch_add(1, Ordering::SeqCst);
            let new_state = !state.fetch_xor(true, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({"block_forward": new_state}))
        })
        .expect(1)
        .mount(&server)
        .await;

    let first_client = client(&server);
    let second_client = client(&server);
    let (first, second) = tokio::join!(
        first_client.set_contact_blocked(AliasId(91), ContactId(74), true),
        second_client.set_contact_blocked(AliasId(91), ContactId(74), true)
    );
    assert!(first.expect("first block should succeed").block_forward);
    assert!(
        second
            .expect("second block should be idempotent")
            .block_forward
    );
    assert!(blocked.load(Ordering::SeqCst));
    assert_eq!(toggle_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejects_impossible_or_conflicting_provider_identity() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/92"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(93, true)))
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/aliases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "aliases": [alias_json(94, true), alias_json(94, false)]
        })))
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/95"))
        .respond_with(ResponseTemplate::new(200).set_body_json(alias_json(95, true)))
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/95/toggle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"enabled": true})))
        .mount(&server)
        .await;
    let mut zero = alias_json(96, true);
    zero["id"] = json!(0);
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/alias/random/new"))
        .respond_with(ResponseTemplate::new(201).set_body_json(zero))
        .mount(&server)
        .await;
    let mut conflicting_mailbox = alias_json(102, true);
    conflicting_mailbox["mailbox"]["id"] = json!(999);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/102"))
        .respond_with(ResponseTemplate::new(200).set_body_json(conflicting_mailbox))
        .mount(&server)
        .await;

    let client = client(&server);
    assert!(matches!(
        client.get_alias(AliasId(92)).await,
        Err(AliasError::InvalidResponseValue(
            "provider returned a different alias identifier"
        ))
    ));
    assert!(matches!(
        client.list_aliases(ListAliasesRequest::default()).await,
        Err(AliasError::InvalidResponseValue(
            "provider returned a zero or duplicate stable identifier"
        ))
    ));
    assert!(matches!(
        client.set_alias_enabled(AliasId(95), false).await,
        Err(AliasError::ConcurrentMutation {
            operation: "alias state change"
        })
    ));
    assert!(matches!(
        client
            .create_random_alias(CreateRandomAliasRequest::default())
            .await,
        Err(AliasError::MutationResponseInvalid {
            operation: "random-alias creation"
        })
    ));
    assert!(matches!(
        client.get_alias(AliasId(102)).await,
        Err(AliasError::InvalidResponseValue(
            "provider returned conflicting alias mailbox identity"
        ))
    ));
}

#[tokio::test]
async fn reports_partial_state_failure_without_replaying_the_mutation() {
    let server = MockServer::start().await;
    let reads = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::clone(&reads);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/97"))
        .respond_with(move |_: &wiremock::Request| {
            if read_count.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(alias_json(97, true))
            } else {
                ResponseTemplate::new(503).set_body_json(json!({"error": "detail unavailable"}))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/97/toggle"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"enabled": false})))
        .expect(1)
        .mount(&server)
        .await;

    let error = client(&server)
        .set_alias_enabled(AliasId(97), false)
        .await
        .expect_err("a failed refresh must not be reported as a successful state change");
    assert!(matches!(
        error,
        AliasError::MutationCommittedButRefreshFailed {
            operation: "alias state change"
        }
    ));
}

#[tokio::test]
async fn converges_after_a_cross_process_alias_toggle_race() {
    let server = MockServer::start().await;
    let enabled = Arc::new(AtomicBool::new(true));
    let interfere_once = Arc::new(AtomicBool::new(true));

    let state = Arc::clone(&enabled);
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/aliases/103"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(200).set_body_json(alias_json(103, state.load(Ordering::SeqCst)))
        })
        .expect(3)
        .mount(&server)
        .await;

    let state = Arc::clone(&enabled);
    let interference = Arc::clone(&interfere_once);
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/api/aliases/103/toggle"))
        .respond_with(move |_: &wiremock::Request| {
            let toggled = !state.fetch_xor(true, Ordering::SeqCst);
            let observed = if interference.swap(false, Ordering::SeqCst) {
                // Simulate another process toggling the alias again before this response is read.
                state.store(true, Ordering::SeqCst);
                true
            } else {
                toggled
            };
            ResponseTemplate::new(200).set_body_json(json!({"enabled": observed}))
        })
        .expect(2)
        .mount(&server)
        .await;

    let state = client(&server)
        .set_alias_enabled(AliasId(103), false)
        .await
        .expect("bounded reconciliation should converge");
    assert!(!state.enabled);
    assert!(!enabled.load(Ordering::SeqCst));
}

#[tokio::test]
async fn mutation_transport_failures_report_an_unknown_outcome_without_replay() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("raw server should bind");
    let address = listener
        .local_addr()
        .expect("raw server should have an address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("raw server should accept");
        let mut request = [0_u8; 4096];
        let length = stream
            .read(&mut request)
            .expect("request should be readable");
        // Dropping the socket without a response leaves the mutation result unknowable.
        String::from_utf8_lossy(&request[..length]).into_owned()
    });

    let error = SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
        CONNECTION_ID.to_owned(),
        format!("http://{address}/"),
        SensitiveString::from(TOKEN),
    ))
    .expect("loopback HTTP should be valid")
    .delete_alias(AliasId(104))
    .await
    .expect_err("a dropped mutation response must be ambiguous");
    assert!(matches!(
        error,
        AliasError::MutationOutcomeUnknown {
            operation: "alias deletion"
        }
    ));
    let request = server.join().expect("raw server should finish");
    assert!(request.starts_with("DELETE /api/aliases/104 "));
}

#[tokio::test]
async fn rejects_invalid_requests_before_dispatch() {
    let server = MockServer::start().await;
    let client = client(&server);
    let invalid_hostname = SensitiveString::from("h".repeat(254));
    assert!(matches!(
        client
            .create_random_alias(CreateRandomAliasRequest {
                hostname: Some(invalid_hostname),
                ..CreateRandomAliasRequest::default()
            })
            .await,
        Err(AliasError::InvalidRequest(_))
    ));
    assert!(matches!(
        client.get_alias(AliasId(0)).await,
        Err(AliasError::InvalidRequest(_))
    ));
    assert!(matches!(
        client
            .create_reverse_alias(AliasId(105), SensitiveString::from("not-an-email"))
            .await,
        Err(AliasError::InvalidRequest(_))
    ));
    assert!(matches!(
        client.delete_alias(AliasId(0)).await,
        Err(AliasError::InvalidRequest(_))
    ));
    assert!(
        server
            .received_requests()
            .await
            .expect("request recording should be enabled")
            .is_empty()
    );
}

#[tokio::test]
async fn keeps_concurrent_pagination_results_bound_to_the_requested_page() {
    let server = MockServer::start().await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/aliases"))
        .and(matchers::query_param("page_id", "0"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(30))
                .set_body_json(json!({"aliases": [alias_json(98, true)]})),
        )
        .mount(&server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/api/v2/aliases"))
        .and(matchers::query_param("page_id", "1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"aliases": [alias_json(99, true)]})),
        )
        .mount(&server)
        .await;

    let client = client(&server);
    let (first, second) = tokio::join!(
        client.list_aliases(ListAliasesRequest {
            page: 0,
            filter: None,
        }),
        client.list_aliases(ListAliasesRequest {
            page: 1,
            filter: None,
        })
    );
    let first = first.expect("first page should succeed");
    let second = second.expect("second page should succeed");
    assert_eq!((first.page, first.aliases[0].id), (0, AliasId(98)));
    assert_eq!((second.page, second.aliases[0].id), (1, AliasId(99)));
}

#[tokio::test]
async fn bounds_chunked_success_and_error_bodies_without_trusting_content_length() {
    for (status, limit) in [(200, 512 * 1024), (500, 16 * 1024)] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("raw server should bind");
        let address = listener
            .local_addr()
            .expect("raw server should have an address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("raw server should accept");
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            let headers = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(headers.as_bytes())
                .expect("raw headers should write");
            let chunk = vec![b'x'; 4096];
            for _ in 0..=(limit / chunk.len()) {
                if write!(stream, "{:x}\r\n", chunk.len()).is_err()
                    || stream.write_all(&chunk).is_err()
                    || stream.write_all(b"\r\n").is_err()
                {
                    break;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let error = SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
            CONNECTION_ID.to_owned(),
            format!("http://{address}/"),
            SensitiveString::from(TOKEN),
        ))
        .expect("raw server URL should be valid")
        .list_aliases(ListAliasesRequest::default())
        .await
        .expect_err("chunked oversized body must fail");
        assert!(matches!(
            error,
            AliasError::ResponseTooLarge { limit_bytes } if limit_bytes == limit
        ));
        server.join().expect("raw server should finish");
    }
}

#[tokio::test]
async fn strips_urls_and_secrets_from_transport_error_display_and_debug() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port should bind");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    drop(listener);
    let path_secret = "sensitive-instance-path";
    let hostname_secret = SensitiveString::from("private-hostname.example");
    let token = "transport-secret-token";
    let error = SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
        CONNECTION_ID.to_owned(),
        format!("http://{address}/{path_secret}/"),
        SensitiveString::from(token),
    ))
    .expect("transport test client should be valid")
    .create_random_alias(CreateRandomAliasRequest {
        hostname: Some(hostname_secret.clone()),
        ..CreateRandomAliasRequest::default()
    })
    .await
    .expect_err("closed port should fail");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(token));
        assert!(!rendered.contains(path_secret));
        assert!(!rendered.contains(hostname_secret.expose()));
        assert!(!rendered.contains(&format!("http://{address}")));
    }
}

#[test]
fn settings_and_sensitive_models_respect_sensitive_debug_mode() {
    let private_base_url = "https://provider.example/private-instance-path/";
    let settings = SimpleLoginAdapterSettings::new(
        CONNECTION_ID.to_owned(),
        private_base_url.to_owned(),
        SensitiveString::from(TOKEN),
    );
    let rendered = format!("{settings:?}");
    assert_eq!(
        rendered.contains(TOKEN),
        format!("{:?}", SensitiveString::from(TOKEN)).contains(TOKEN)
    );
    assert!(!rendered.contains(private_base_url));
    assert!(!rendered.contains("private-instance-path"));
    assert!(rendered.contains("[REDACTED]"));

    assert!(matches!(
        SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
            CONNECTION_ID.to_owned(),
            "https://user:password@example.test".to_owned(),
            SensitiveString::from(TOKEN),
        )),
        Err(AliasError::InvalidBaseUrl(_))
    ));
    assert!(matches!(
        SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
            CONNECTION_ID.to_owned(),
            "https://example.test".to_owned(),
            SensitiveString::from("bad\ntoken"),
        )),
        Err(AliasError::InvalidAuthenticationToken)
    ));
    assert!(matches!(
        SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
            CONNECTION_ID.to_owned(),
            "https://example.test".to_owned(),
            SensitiveString::from(""),
        )),
        Err(AliasError::InvalidAuthenticationToken)
    ));

    for hostile in [
        "file:///etc/passwd",
        "https://user@example.test/",
        "https://example.test/?token=secret",
        "https://example.test/#secret",
        "http://example.test/",
        "http://192.168.1.7/",
        "//example.test/",
    ] {
        assert!(matches!(
            SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
                CONNECTION_ID.to_owned(),
                hostile.to_owned(),
                SensitiveString::from(TOKEN),
            )),
            Err(AliasError::InvalidBaseUrl(_))
        ));
    }

    for loopback in [
        "http://localhost/",
        "http://service.localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ] {
        SimpleLoginTransport::new(SimpleLoginAdapterSettings::new(
            CONNECTION_ID.to_owned(),
            loopback.to_owned(),
            SensitiveString::from(TOKEN),
        ))
        .expect("loopback self-hosted HTTP should remain available for local labs");
    }
}
