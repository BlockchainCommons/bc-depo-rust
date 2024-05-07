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
use bc_components::{PublicKeyBase, PrivateKeyBase};
use nu_ansi_term::Color::{Cyan, Red, Yellow};
use anyhow::Result;
use depo_api::{
    request::store_share::StoreShareRequest, DeleteAccountRequest, DeleteSharesRequest,
    FinishRecoveryRequest, GetRecoveryRequest, GetRecoveryResponse, GetSharesRequest,
    GetSharesResponse, StartRecoveryRequest, StartRecoveryResponse, StoreShareResponse,
    UpdateKeyRequest, UpdateRecoveryRequest,
};

/// Test against the Depo API that stores data in memory.
#[tokio::test]
async fn test_in_memory_depo() {
    setup_log();
    let depo = Depo::new_in_memory();
    test_depo_scenario(depo.public_key(), &depo).await;
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
    test_depo_scenario(depo.public_key(), &depo).await;
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

    test_depo_scenario(depo_public_key, &depo).await;
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

    test_depo_scenario(&depo_public_key, &depo).await;
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
    request: impl EnvelopeEncodable,
    client_private_key: &PrivateKeyBase,
    depo_public_key: &PublicKeyBase,
    depo: &impl RequestHandler,
) -> Envelope {
    let request = request.into_envelope();
    let encrypted_request = request.seal(client_private_key, depo_public_key).unwrap();

    let raw_response = depo.handle_encrypted_request(encrypted_request).await;

    if raw_response.is_failure() {
        return raw_response;
    }
    let response = raw_response.unseal(depo_public_key, client_private_key).unwrap();
    assert_eq!(
        response.response_id().unwrap(),
        request.request_id().unwrap()
    );
    response
}

pub async fn test_depo_scenario(depo_public_key: &PublicKeyBase, depo: &impl RequestHandler) {
    info!("{}", Cyan.paint("=== Alice stores a share"));
    let alice_private_key = PrivateKeyBase::new();
    let alice_public_key = alice_private_key.public_key();
    let alice_data_1 = Bytes::from_static(&hex!("cafebabe"));
    let request = StoreShareRequest::new(&alice_public_key, &alice_data_1);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = StoreShareResponse::try_from(response_envelope).unwrap();
    let alice_receipt_1 = response.receipt();

    info!("{}", Cyan.paint("=== Bob stores a share"));
    let bob_private_key = PrivateKeyBase::new();
    let bob_public_key = bob_private_key.public_key();
    let bob_data_1 = Bytes::from_static(&hex!("deadbeef"));
    let request = StoreShareRequest::new(&bob_public_key, &bob_data_1);
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    let response = StoreShareResponse::try_from(response_envelope).unwrap();
    let bob_receipt_1 = response.receipt();

    info!("{}", Cyan.paint("=== Alice retrieves her share"));
    let request = GetSharesRequest::new(&alice_public_key, vec![&alice_receipt_1]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    let alice_retrieved_data_1 = response.data_for_receipt(&alice_receipt_1).unwrap();
    assert_eq!(alice_retrieved_data_1, alice_data_1);

    info!("{}", Cyan.paint("=== Bob retrieves his share"));
    let request = GetSharesRequest::new(&bob_public_key, vec![&bob_receipt_1]);
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    let bob_retrieved_data_1 = response.data_for_receipt(&bob_receipt_1).unwrap();
    assert_eq!(bob_retrieved_data_1, bob_data_1);

    info!("{}", Cyan.paint("=== Alice stores a second share"));
    let alice_data_2 = Bytes::from_static(&hex!("cafef00d"));
    let request = StoreShareRequest::new(&alice_public_key, &alice_data_2);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = StoreShareResponse::try_from(response_envelope).unwrap();
    let alice_receipt_2 = response.receipt();

    info!("{}", Cyan.paint("=== Alice retrieves her second share"));
    let request = GetSharesRequest::new(&alice_public_key, vec![&alice_receipt_2]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    let alice_retrieved_data_2 = response.data_for_receipt(&alice_receipt_2).unwrap();
    assert_eq!(alice_retrieved_data_2, alice_data_2);

    info!("{}", Cyan.paint("=== Alice retrieves both her shares identified only by her public key"));
    let request = GetSharesRequest::new(&alice_public_key, vec![]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.receipt_to_data().len(), 2);

    info!("{}", Cyan.paint("=== Bob attempts to retrieve one of Alice's shares"));
    let request = GetSharesRequest::new(&bob_public_key, vec![&alice_receipt_1]);
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.receipt_to_data().len(), 0);

    info!("{}", Red.paint("=== Someone attempts to retrieve all shares from a nonexistent account"));
    let nonexistent_private_key = PrivateKeyBase::new();
    let nonexistent_public_key = nonexistent_private_key.public_key();
    let request = GetSharesRequest::new(&nonexistent_public_key, vec![]);
    let response_envelope = server_call(request, &nonexistent_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

    info!("{}", Red.paint("=== Someone attempts to retrieve all shares from Alice's account using her public key"));
    let request = GetSharesRequest::new(&alice_public_key, vec![]);
    let response_envelope = server_call(request, &nonexistent_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("could not verify a signature"));

    info!("{}", Red.paint("=== Alice attempts to retrieve her shares using the incorrect depo public key"));
    let request = GetSharesRequest::new(&alice_public_key, vec![]);
    let response_envelope = server_call(request, &alice_private_key, &nonexistent_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("no recipient matches the given key"));

    info!("{}", Cyan.paint("=== Alice stores a share she's previously stored (idempotent)"));
    let request = StoreShareRequest::new(&alice_public_key, alice_data_1);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = StoreShareResponse::try_from(response_envelope).unwrap();
    let alice_receipt_3 = response.receipt();
    assert_eq!(alice_receipt_3, alice_receipt_1);

    info!("{}", Cyan.paint("=== Alice deletes one of her shares"));
    let request = DeleteSharesRequest::new(&alice_public_key, vec![&alice_receipt_1]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    let request = GetSharesRequest::new(&alice_public_key, vec![]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.receipt_to_data().len(), 1);
    let alice_retrieved_data_2 = response.data_for_receipt(&alice_receipt_2).unwrap();
    assert_eq!(alice_retrieved_data_2, alice_data_2);

    info!("{}", Cyan.paint("=== Alice attempts to delete a share she already deleted (idempotent)"));
    let request = DeleteSharesRequest::new(&alice_public_key, vec![&alice_receipt_1]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    let request = GetSharesRequest::new(&alice_public_key, vec![]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.receipt_to_data().len(), 1);
    let alice_retrieved_data_2 = response.data_for_receipt(&alice_receipt_2).unwrap();
    assert_eq!(alice_retrieved_data_2, alice_data_2);

    info!("{}", Cyan.paint("=== Bob adds a recovery method"));
    let bob_recovery = "bob@example.com";
    let request = UpdateRecoveryRequest::new(&bob_public_key, Some(bob_recovery));
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    info!("{}", Cyan.paint("=== Bob sets the same recovery method again (idempotent)"));
    let request = UpdateRecoveryRequest::new(&bob_public_key, Some(bob_recovery));
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    info!("{}", Cyan.paint("=== Bob gets his recovery method"));
    let request = GetRecoveryRequest::new(&bob_public_key);
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    let response = GetRecoveryResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.recovery(), Some(bob_recovery));

    info!("{}", Cyan.paint("=== Alice gets her recovery method, but she has none"));
    let request = GetRecoveryRequest::new(&alice_public_key);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    let response = GetRecoveryResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.recovery(), None);

    info!("{}", Red.paint("=== Alice attempts to add a non-unique recovery method"));
    let request = UpdateRecoveryRequest::new(&alice_public_key, Some(bob_recovery));
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("recovery method already exists"));

    info!("{}", Red.paint("=== Someone attempts to retrieve the recovery method for a nonexistent account"));
    let request = GetRecoveryRequest::new(&nonexistent_public_key);
    let response_envelope = server_call(request, &nonexistent_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

    info!("{}", Cyan.paint("=== Alice updates her public key to a new one"));
    let alice_private_key_2 = PrivateKeyBase::new();
    let alice_public_key_2 = alice_private_key_2.public_key();
    let request = UpdateKeyRequest::new(&alice_public_key, &alice_public_key_2);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    info!("{}", Red.paint("=== Alice can no longer retrieve her shares using the old public key"));
    let request = GetSharesRequest::new(&alice_public_key, vec![]);
    let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

    info!("{}", Cyan.paint("=== Alice must now use her new public key"));
    let request = GetSharesRequest::new(&alice_public_key_2, vec![]);
    let response_envelope = server_call(request, &alice_private_key_2, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.receipt_to_data().len(), 1);

    info!("{}", Cyan.paint("=== Bob has lost his public key, so he wants to replace it with a new one"));
    let bob_private_key_2 = PrivateKeyBase::new();
    let bob_public_key_2 = bob_private_key_2.public_key();

    info!("{}", Red.paint("=== Bob requests transfer using an incorrect recovery method"));
    let incorrect_recovery = "wrong@example.com";
    let request = StartRecoveryRequest::new(&bob_public_key_2, incorrect_recovery);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown recovery"));

    info!("{}", Cyan.paint("=== Bob requests a transfer using the correct recovery method"));
    let request = StartRecoveryRequest::new(&bob_public_key_2, bob_recovery);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    let response = StartRecoveryResponse::try_from(response_envelope).unwrap();

    // The recovery continuation is both signed by the server and encrypted to
    // the server, and is also time-limited. It is sent to Bob's recovery
    // contact method, which acts as a second factor. Once in possession of the
    // recovery continuation, Bob can use it to finish the recovery process.
    //
    // For testing purposes only, we're allowed to skip the second factor and
    // get the recovery continuation directly.
    let continuation = response.continuation();

    info!("{}", Red.paint("=== Bob attempts to use the recovery continuation to finish setting his new public key, but the request is signed by his old key"));
    let request = FinishRecoveryRequest::new(&bob_public_key, continuation.clone());
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("invalid user signing key"));

    info!("{}", Cyan.paint("=== Bob uses the recovery continuation to finish setting his new public key, properly signed by his new key"));
    let request = FinishRecoveryRequest::new(&bob_public_key_2, continuation);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    info!("{}", Red.paint("=== Bob can no longer retrieve his shares using the old public key"));
    let request = GetSharesRequest::new(&bob_public_key, vec![]);
    let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

    info!("{}", Cyan.paint("=== Bob must now use his new public key"));
    let request = GetSharesRequest::new(&bob_public_key_2, vec![]);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    let response = GetSharesResponse::try_from(response_envelope).unwrap();
    assert_eq!(response.receipt_to_data().len(), 1);

    info!("{}", Cyan.paint("=== Bob decides to delete his account"));
    let request = DeleteAccountRequest::new(&bob_public_key_2);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    info!("{}", Red.paint("=== Bob can no longer retrieve his shares using the new public key"));
    let request = GetSharesRequest::new(&bob_public_key_2, vec![]);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

    info!("{}", Red.paint("=== Attempting to retrieve his recovery method now throws an error"));
    let request = GetRecoveryRequest::new(&bob_public_key_2);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

    info!("{}", Cyan.paint("=== Deleting an account is idempotent"));
    let request = DeleteAccountRequest::new(&bob_public_key_2);
    let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());

    info!("{}", Cyan.paint("=== Alice deletes her account"));
    let request = DeleteAccountRequest::new(&alice_public_key_2);
    let response_envelope = server_call(request, &alice_private_key_2, depo_public_key, depo).await;
    assert!(response_envelope.is_result_ok().unwrap());
}
