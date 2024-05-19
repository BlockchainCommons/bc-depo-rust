use async_trait::async_trait;
use bytes::Bytes;
use bc_envelope::prelude::*;
use depo::{Depo, start_server, setup_log, create_db_if_needed};
use log::{warn, info};
use reqwest::{self, Client, StatusCode};
use hex_literal::hex;
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
    StartRecoveryResult,
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
    setup_log();
    let depo = Depo::new_in_memory();
    let context = Context::new(depo.public_key(), &depo);
    test_depo_scenario(&context).await;
}

/// Test against the Depo API that stores data in a database.
/// Requires a MySQL or MariaDB server running on localhost.
#[tokio::test]
async fn test_db_depo() {
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
    context: &Context<'_>,
) -> Result<SealedResponse> {
    let id = ARID::new();
    let sender = client_private_key.public_key();
    let sealed_request = SealedRequest::new_with_body(body.to_expression(), id, sender);
    let encrypted_request = (sealed_request, client_private_key, context.depo_public_key).into();

    let raw_response = context.depo.handle_encrypted_request(encrypted_request).await;

    (raw_response, client_private_key).try_into()
}

async fn server_call_ok(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    context: &Context<'_>,
) {
    let sealed_response = server_call(body, client_private_key, context).await.unwrap();
    assert!(sealed_response.is_ok());
}

async fn server_call_ok_into_result<T>(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    context: &Context<'_>,
) -> T
where
    T: TryFrom<SealedResponse>,
    <T as TryFrom<SealedResponse>>::Error: std::fmt::Debug
{
    server_call(body, client_private_key, context).await.unwrap().try_into().unwrap()
}

async fn server_call_error_contains(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    context: &Context<'_>,
    expected_error: &str,
) {
    let sealed_response = server_call(body, client_private_key, context).await.unwrap();
    assert!(sealed_response.extract_error::<String>().unwrap().contains(expected_error));
}

async fn server_call_early_error_contains(
    body: &dyn IntoExpression,
    client_private_key: &PrivateKeyBase,
    context: &Context<'_>,
    expected_error: &str,
) {
    let early_result = server_call(body, client_private_key, context).await;
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

pub async fn test_depo_scenario(context: &Context<'_>) {
    let alice = PrivateKeyBase::new();
    let bob = PrivateKeyBase::new();

    section!("Alice stores a share");
    let alice_data_1 = Bytes::from_static(&hex!("cafebabe"));
    let body = StoreShare::new(alice_data_1.clone());
    let result: StoreShareResult = server_call_ok_into_result(&body, &alice, context).await;
    let alice_receipt_1 = result.receipt();

    section!("Bob stores a share");
    let bob_data_1 = Bytes::from_static(&hex!("deadbeef"));
    let body = StoreShare::new(bob_data_1.clone());
    let result: StoreShareResult = server_call_ok_into_result(&body, &bob, context).await;
    let bob_receipt_1 = result.receipt();

    section!("Alice retrieves her share");
    let body = GetShares::new(vec![alice_receipt_1]);
    let result: GetSharesResult = server_call_ok_into_result(&body, &alice, context).await;
    assert_eq!(result.data_for_receipt(alice_receipt_1), Some(&alice_data_1));

    section!("Bob retrieves his share");
    let body = GetShares::new(vec![bob_receipt_1]);
    let result: GetSharesResult = server_call_ok_into_result(&body, &bob, context).await;
    assert_eq!(result.data_for_receipt(bob_receipt_1), Some(&bob_data_1));

    section!("Alice stores a second share");
    let alice_data_2 = Bytes::from_static(&hex!("cafef00d"));
    let body = StoreShare::new(alice_data_2.clone());
    let result: StoreShareResult = server_call_ok_into_result(&body, &alice, context).await;
    let alice_receipt_2 = result.receipt();

    section!("Alice retrieves her second share");
    let body = GetShares::new(vec![alice_receipt_2]);
    let result: GetSharesResult = server_call_ok_into_result(&body, &alice, context).await;
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Alice retrieves both her shares identified only by her public key");
    let body = GetShares::new_all_shares();
    let result: GetSharesResult = server_call_ok_into_result(&body, &alice, context).await;
    assert_eq!(result.receipt_to_data().len(), 2);
    assert_eq!(result.data_for_receipt(alice_receipt_1), Some(&alice_data_1));
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Bob attempts to retrieve one of Alice's shares");
    let body = GetShares::new(vec![alice_receipt_1]);
    let result: GetSharesResult = server_call_ok_into_result(&body, &bob, context).await;
    assert_eq!(result.receipt_to_data().len(), 0);

    alert!("Someone attempts to retrieve all shares from a nonexistent account");
    let nonexistent_private_key = PrivateKeyBase::new();
    let nonexistent_public_key = nonexistent_private_key.public_key();
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &nonexistent_private_key, context, "unknown public key").await;

    alert!("Alice attempts to retrieve her shares using the incorrect depo public key");
    let body = GetShares::new_all_shares();
    server_call_early_error_contains(&body, &alice, &context.with_public_key(&nonexistent_public_key), "unknown recipient").await;

    section!("Alice stores a share she's previously stored (idempotent)");
    let body = StoreShare::new(alice_data_1.clone());
    let result: StoreShareResult = server_call_ok_into_result(&body, &alice, context).await;
    let alice_receipt_3 = result.receipt();
    assert_eq!(alice_receipt_3, alice_receipt_1);

    section!("Alice deletes one of her shares");
    let body = DeleteShares::new(vec![alice_receipt_1]);
    server_call_ok(&body, &alice, context).await;

    let body = GetShares::new_all_shares();
    let result: GetSharesResult = server_call_ok_into_result(&body, &alice, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Alice attempts to delete a share she already deleted (idempotent)");
    let body = DeleteShares::new(vec![alice_receipt_1]);
    server_call_ok(&body, &alice, context).await;

    let body = GetShares::new_all_shares();
    let result: GetSharesResult = server_call_ok_into_result(&body, &alice, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);
    assert_eq!(result.data_for_receipt(alice_receipt_2), Some(&alice_data_2));

    section!("Bob adds a recovery method");
    let bob_recovery = "bob@example.com";
    let body = UpdateRecovery::new(Some(bob_recovery.to_string()));
    server_call_ok(&body, &bob, context).await;

    section!("Bob sets the same recovery method again (idempotent)");
    let body = UpdateRecovery::new(Some(bob_recovery.to_string()));
    server_call_ok(&body, &bob, context).await;

    section!("Bob gets his recovery method");
    let body = GetRecovery::new();
    let result: GetRecoveryResult = server_call_ok_into_result(&body, &bob, context).await;
    assert_eq!(result.recovery(), Some(bob_recovery));

    section!("Alice gets her recovery method, but she has none");
    let body = GetRecovery::new();
    let result: GetRecoveryResult = server_call_ok_into_result(&body, &alice, context).await;
    assert_eq!(result.recovery(), None);

    alert!("Alice attempts to add a non-unique recovery method");
    let body = UpdateRecovery::new(Some(bob_recovery.to_string()));
    server_call_error_contains(&body, &alice, context, "recovery method already exists").await;

    alert!("Someone attempts to retrieve the recovery method for a nonexistent account");
    let body = GetRecovery::new();
    server_call_error_contains(&body, &nonexistent_private_key, context, "unknown public key").await;

    section!("Alice updates her public key to a new one");
    let alice_private_key_2 = PrivateKeyBase::new();
    let alice_public_key_2 = alice_private_key_2.public_key();
    let body = UpdateKey::new(alice_public_key_2.clone());
    server_call_ok(&body, &alice, context).await;

    alert!("Alice can no longer retrieve her shares using the old public key");
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &alice, context, "unknown public key").await;

    section!("Alice must now use her new public key");
    let body = GetShares::new_all_shares();
    let result: GetSharesResult = server_call_ok_into_result(&body, &alice_private_key_2, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);

    section!("Bob has lost his public key, so he wants to replace it with a new one");
    let bob_private_key_2 = PrivateKeyBase::new();

    alert!("Bob requests transfer using an incorrect recovery method");
    let incorrect_recovery = "wrong@example.com";
    let body = StartRecovery::new(incorrect_recovery.to_string());
    server_call_error_contains(&body, &bob_private_key_2, context, "unknown recovery").await;

    section!("Bob requests a transfer using the correct recovery method");
    let body = StartRecovery::new(bob_recovery.to_string());
    let result: StartRecoveryResult = server_call_ok_into_result(&body, &bob_private_key_2, context).await;

    // The recovery continuation is both signed by the server and encrypted to
    // the server, and is also time-limited. It is sent to Bob's recovery
    // contact method, which acts as a second factor. Once in possession of the
    // recovery continuation, Bob can use it to finish the recovery process.
    //
    // For testing purposes only, we're allowed to skip the second factor and
    // get the recovery continuation directly.
    let continuation = result.continuation();

    alert!("Bob attempts to use the recovery continuation to finish setting his new public key, but the request is signed by his old key");
    let body = FinishRecovery::new(continuation.clone());
    server_call_error_contains(&body, &bob, context, "invalid user signing key").await;

    section!("Bob uses the recovery continuation to finish setting his new public key, properly signed by his new key");
    let body = FinishRecovery::new(continuation.clone());
    server_call_ok(&body, &bob_private_key_2, context).await;

    alert!("Bob can no longer retrieve his shares using the old public key");
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &bob, context, "unknown public key").await;

    section!("Bob must now use his new public key");
    let body = GetShares::new_all_shares();
    let result: GetSharesResult = server_call_ok_into_result(&body, &bob_private_key_2, context).await;
    assert_eq!(result.receipt_to_data().len(), 1);

    section!("Bob decides to delete his account");
    let body = DeleteAccount::new();
    server_call_ok(&body, &bob_private_key_2, context).await;

    alert!("Bob can no longer retrieve his shares using the new public key");
    let body = GetShares::new_all_shares();
    server_call_error_contains(&body, &bob_private_key_2, context, "unknown public key").await;

    alert!("Attempting to retrieve his recovery method now throws an error");
    let body = GetRecovery::new();
    server_call_error_contains(&body, &bob_private_key_2, context, "unknown public key").await;

    section!("Deleting an account is idempotent");
    let body = DeleteAccount::new();
    server_call_ok(&body, &bob_private_key_2, context).await;

    section!("Alice deletes her account");
    let body = DeleteAccount::new();
    server_call_ok(&body, &alice_private_key_2, context).await;
}
