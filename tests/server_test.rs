use async_trait::async_trait;
use bc_envelope::prelude::*;
use depo::{Depo, start_server, setup_log, create_db_if_needed};
use log::{warn, info};
use reqwest::{self, Client, StatusCode};
use tokio::time::sleep;
use std::time::Duration;
use url::Url;
use bc_components::{PrivateKeyBase, PublicKeyBase, ARID};
use nu_ansi_term::Color::{Red, Blue, Yellow};
use anyhow::Result;
use depo_api::{
    DeleteAccount,
    DeleteShares,
    FinishRecovery,
    GetRecovery,
    GetRecoveryResult,
    GetShares,
    GetSharesResult,
    StartRecovery,
    StoreShare,
    StoreShareResult,
    UpdateKey,
    UpdateRecovery,
};

pub struct Context<'a> {
    depo_public_key: &'a PublicKeyBase,
    depo: &'a dyn RequestHandler,
}

impl Context<'_> {
    fn new<'a>(depo_public_key: &'a PublicKeyBase, depo: &'a dyn RequestHandler) -> Context<'a> {
        Context { depo_public_key, depo }
    }

    fn with_public_key<'a>(&'a self, public_key: &'a PublicKeyBase) -> Context<'_> {
        Context::new(public_key, self.depo)
    }
}

/// Test against the Depo API that stores data in memory.
#[tokio::test]
async fn test_in_memory_depo() {
    bc_envelope::register_tags();
    setup_log();
    let depo = Depo::new_in_memory();
    let context = Context::new(depo.public_key(), &depo);
    test_depo_scenario(&context).await;
}

/// Test against the Depo API that stores data in a database.
/// Requires a MySQL or MariaDB server running on localhost.
#[tokio::test]
async fn test_db_depo() {
    bc_envelope::register_tags();
    setup_log();
    let schema_name = "test_db_depo";
    if let Err(e) = create_db_if_needed(schema_name).await {
        warn!("{}", Yellow.paint(format!("Skipping `{}` because can't connect to the database.", schema_name)).to_string());
        warn!("{}", Yellow.paint(format!("{}", e)).to_string());
        return;
    }

    let depo = Depo::new_db(schema_name).await.unwrap();
    let context = Context::new(depo.public_key(), &depo);
    test_depo_scenario(&context).await;
}

/// Test against the full Depo HTTP server running in a separate thread.
/// Requires a MySQL or MariaDB server running on localhost.
#[tokio::test]
async fn test_server_depo() {
    bc_envelope::register_tags();
    setup_log();
    let schema_name = "test_server_depo";
    let port: u16 = 5333;
    if let Err(e) = create_db_if_needed(schema_name).await {
        warn!("{}", Yellow.paint(format!("Skipping `{}` because can't connect to the database.", schema_name)).to_string());
        warn!("{}", Yellow.paint(format!("{}", e)).to_string());
        return;
    }

    // Start the server and wait for it to be ready
    tokio::spawn(async move {
        start_server(schema_name, port).await.unwrap();
    });
    sleep(Duration::from_secs(1)).await;

    // Start the client
    let depo = ClientRequestHandler::new(port);

    let depo_public_key = &get_public_key(&depo).await.unwrap();

    let context = Context::new(depo_public_key, &depo);
    test_depo_scenario(&context).await;
}

/// Test against the full Depo HTTP server running in separate process.
#[tokio::test]
async fn test_server_separate() {
    bc_envelope::register_tags();
    setup_log();

    let port: u16 = 5332;
    let depo = ClientRequestHandler::new(port);

    // skip test if error
    let depo_public_key = match get_public_key(&depo).await {
        Ok(key) => key,
        Err(e) => {
            warn!("{}", Yellow.paint(format!("Skipping `{}` because can't connect to the depo server.", "test_server_separate")).to_string());
            warn!("{}", Yellow.paint(format!("{}", e)).to_string());
            return;
        }
    };

    let context = Context::new(&depo_public_key, &depo);
    test_depo_scenario(&context).await;
}

#[async_trait]
pub trait RequestHandler {
    async fn handle_encrypted_request(&self, encrypted_request: Envelope) -> Envelope;
}

#[async_trait]
impl RequestHandler for Depo {
    async fn handle_encrypted_request(&self, encrypted_request: Envelope) -> Envelope {
        self.handle_request(encrypted_request).await
    }
}

struct ClientRequestHandler {
    client: Client,
    port: u16,
}

impl ClientRequestHandler {
    fn new(port: u16) -> Self {
        Self {
            client: Client::new(),
            port,
        }
    }
}

#[async_trait]
impl RequestHandler for ClientRequestHandler {
    async fn handle_encrypted_request(&self, encrypted_request: Envelope) -> Envelope {
        let body = encrypted_request.ur_string();
        let resp = self.client.post(url(self.port)).body(body).send().await.unwrap();
        let raw_response_string = resp.text().await.unwrap();
        Envelope::from_ur_string(raw_response_string).unwrap()
    }
}

fn url(port: u16) -> Url {
    let mut url = Url::parse("http://localhost").unwrap();
    url.set_port(Some(port)).unwrap();
    url
}

async fn get_public_key(client: &ClientRequestHandler) -> Result<PublicKeyBase> {
    let resp = client.client.get(url(client.port)).send().await?;

    assert_eq!(resp.status(), StatusCode::OK);
    let string = resp.text().await.unwrap();
    let public_key = PublicKeyBase::from_ur_string(string)?;
    Ok(public_key)
}

async fn server_call(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    peer_continuation: Option<Envelope>,
    context: &Context<'_>,
) -> Result<SealedResponse> {
    let id = ARID::new();
    let sender = client_private_key.schnorr_public_key_base();
    let sealed_request = SealedRequest::new_with_body(body.to_expression(), id, sender)
        .with_optional_peer_continuation(peer_continuation);
    let encrypted_request = (sealed_request, client_private_key, context.depo_public_key).into();

    let raw_response = context.depo.handle_encrypted_request(encrypted_request).await;

    SealedResponse::try_from((raw_response, client_private_key))
}

async fn server_call_ok(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    peer_continuation: Option<Envelope>,
    context: &Context<'_>,
) -> SealedResponse {
    let sealed_response = server_call(body, client_private_key, peer_continuation, context).await.unwrap();
    assert!(sealed_response.is_ok());
    sealed_response
}

async fn server_call_ok_into_result<T>(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    peer_continuation: Option<Envelope>,
    context: &Context<'_>,
) -> (T, SealedResponse)
where
    T: TryFrom<SealedResponse>,
    <T as TryFrom<SealedResponse>>::Error: std::fmt::Debug
{
    let sealed_response = server_call(body, client_private_key, peer_continuation, context).await.unwrap();
    let t = T::try_from(sealed_response.clone()).unwrap();
    (t, sealed_response)
}

async fn server_call_error_contains(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    peer_continuation: Option<Envelope>,
    context: &Context<'_>,
    expected_error: &str,
) -> SealedResponse {
    let sealed_response = server_call(body, client_private_key, peer_continuation, context).await.unwrap();
    assert!(sealed_response.extract_error::<String>().unwrap().contains(expected_error));
    sealed_response
}

async fn server_call_early_error_contains(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    peer_continuation: Option<Envelope>,
    context: &Context<'_>,
    expected_error: &str,
) {
    let early_result = server_call(body, client_private_key, peer_continuation, context).await;
    assert!(early_result.err().unwrap().to_string().contains(expected_error));
}

#[macro_export]
macro_rules! section {
    ($msg:expr) => {
        info!("🔷 {}", Blue.paint($msg));
    };
}

#[macro_export]
macro_rules! alert {
    ($msg:expr) => {
        info!("🛑 {}", Red.paint($msg));
    };
}

fn hex_bytes(hex: &str) -> ByteString {
    hex::decode(hex).unwrap().into()
}

pub async fn test_depo_scenario(context: &Context<'_>) {
    let alice = PrivateKeyBase::new();
    let bob = PrivateKeyBase::new();

    section!("Alice stores a share");
    let alice_data_1 = hex_bytes("cafebabe");
    let body = StoreShare::new(alice_data_1.clone());
    let (result, _): (StoreShareResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    let alice_receipt_1 = result.receipt();

    section!("Bob stores a share");
    let bob_data_1 = hex_bytes("deadbeef");
    let body = StoreShare::new(bob_data_1.clone());
    let (result, _): (StoreShareResult, _) = server_call_ok_into_result(&body, &bob, None, context).await;
    let bob_receipt_1 = result.receipt();

    section!("Alice retrieves her share");
    let body = GetShares::new(vec![alice_receipt_1]);
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.data_for_receipt(alice_receipt_1), Some(&alice_data_1));

    section!("Bob retrieves his share");
    let body = GetShares::new(vec![bob_receipt_1]);
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &bob, None, context).await;
    assert_eq!(result.data_for_receipt(bob_receipt_1), Some(&bob_data_1));

    section!("Alice stores a second share");
    let alice_data_2 = hex_bytes("cafef00d");
    let body = StoreShare::new(alice_data_2.clone());
    let (result, _): (StoreShareResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    let alice_receipt_2 = result.receipt();

    section!("Alice retrieves her second share");
    let body = GetShares::new(vec![alice_receipt_2]);
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Alice retrieves both her shares identified only by her public key");
    let body = GetShares::new_all_shares();
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.receipt_to_data().len(), 2);
    assert_eq!(result.data_for_receipt(alice_receipt_1), Some(&alice_data_1));
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Bob attempts to retrieve one of Alice's shares");
    let body = GetShares::new(vec![alice_receipt_1]);
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &bob, None, context).await;
    assert_eq!(result.receipt_to_data().len(), 0);

    alert!("Someone attempts to retrieve all shares from a nonexistent account");
    let nonexistent_private_key = PrivateKeyBase::new();
    let nonexistent_public_key = nonexistent_private_key.schnorr_public_key_base();
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &nonexistent_private_key, None, context, "unknown public key").await;

    alert!("Alice attempts to retrieve her shares using the incorrect depo public key");
    let body = GetShares::new_all_shares();
    server_call_early_error_contains(&body, &alice, None, &context.with_public_key(&nonexistent_public_key), "unknown recipient").await;

    section!("Alice stores a share she's previously stored (idempotent)");
    let body = StoreShare::new(alice_data_1.clone());
    let (result, _): (StoreShareResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.receipt(), alice_receipt_1);

    section!("Alice deletes one of her shares");
    let body = DeleteShares::new(vec![alice_receipt_1]);
    server_call_ok(&body, &alice, None, context).await;

    let body = GetShares::new_all_shares();
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Alice attempts to delete a share she already deleted (idempotent)");
    let body = DeleteShares::new(vec![alice_receipt_1]);
    server_call_ok(&body, &alice, None, context).await;

    let body = GetShares::new_all_shares();
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Bob adds a recovery method");
    let bob_recovery = "bob@example.com";
    let body = UpdateRecovery::new(Some(bob_recovery.to_string()));
    server_call_ok(&body, &bob, None, context).await;

    section!("Bob sets the same recovery method again (idempotent)");
    let body = UpdateRecovery::new(Some(bob_recovery.to_string()));
    server_call_ok(&body, &bob, None, context).await;

    section!("Bob gets his recovery method");
    let body = GetRecovery::new();
    let (result, _): (GetRecoveryResult, _) = server_call_ok_into_result(&body, &bob, None, context).await;
    assert_eq!(result.recovery(), Some(bob_recovery));

    section!("Alice gets her recovery method, but she has none");
    let body = GetRecovery::new();
    let (result, _): (GetRecoveryResult, _) = server_call_ok_into_result(&body, &alice, None, context).await;
    assert_eq!(result.recovery(), None);

    alert!("Alice attempts to add a non-unique recovery method");
    let body = UpdateRecovery::new(Some(bob_recovery.to_string()));
    server_call_error_contains(&body, &alice, None, context, "recovery method already exists").await;

    alert!("Someone attempts to retrieve the recovery method for a nonexistent account");
    let body = GetRecovery::new();
    server_call_error_contains(&body, &nonexistent_private_key, None, context, "unknown public key").await;

    section!("Alice updates her public key to a new one");
    let alice_2 = PrivateKeyBase::new();
    let body = UpdateKey::new(alice_2.schnorr_public_key_base());
    server_call_ok(&body, &alice, None, context).await;

    alert!("Alice can no longer retrieve her shares using the old public key");
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &alice, None, context, "unknown public key").await;

    section!("Alice must now use her new public key");
    let body = GetShares::new_all_shares();
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &alice_2, None, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);

    section!("Bob has lost his public key, so he wants to replace it with a new one");
    let bob_2 = PrivateKeyBase::new();

    alert!("Bob requests transfer using an incorrect recovery method");
    let incorrect_recovery = "wrong@example.com";
    let body = StartRecovery::new(incorrect_recovery.to_string());
    server_call_error_contains(&body, &bob_2, None, context, "unknown recovery").await;

    section!("Bob requests a transfer using the correct recovery method");
    let body = StartRecovery::new(bob_recovery.to_string());
    let sealed_response: SealedResponse = server_call_ok(&body, &bob_2, None, context).await;

    // The recovery continuation is self-encrypted by the server, and is also
    // time-limited. It is sent to Bob's recovery contact method, which acts as
    // a second factor. Once in possession of the recovery continuation, Bob can
    // use it to finish the recovery process.
    let continuation = sealed_response.peer_continuation().unwrap();

    alert!("Bob attempts to use the recovery continuation to finish setting his new public key, but the request is signed by his old key");
    let body = FinishRecovery::new();
    server_call_error_contains(&body, &bob, Some(continuation.clone()), context, "invalid user signing key").await;

    section!("Bob uses the recovery continuation to finish setting his new public key, properly signed by his new key");
    let body = FinishRecovery::new();
    server_call_ok(&body, &bob_2, Some(continuation.clone()), context).await;

    alert!("Bob can no longer retrieve his shares using the old public key");
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &bob, None, context, "unknown public key").await;

    section!("Bob must now use his new public key");
    let body = GetShares::new_all_shares();
    let (result, _): (GetSharesResult, _) = server_call_ok_into_result(&body, &bob_2, None, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);

    section!("Bob decides to delete his account");
    let body = DeleteAccount::new();
    server_call_ok(&body, &bob_2, None, context).await;

    alert!("Bob can no longer retrieve his shares using the new public key");
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &bob_2, None, context, "unknown public key").await;

    alert!("Attempting to retrieve his recovery method now throws an error");
    let body = GetRecovery::new();
    server_call_error_contains(&body, &bob_2, None, context, "unknown public key").await;

    section!("Deleting an account is idempotent");
    let body = DeleteAccount::new();
    server_call_ok(&body, &bob_2, None, context).await;

    section!("Alice deletes her account");
    let body = DeleteAccount::new();
    server_call_ok(&body, &alice_2, None, context).await;
}
