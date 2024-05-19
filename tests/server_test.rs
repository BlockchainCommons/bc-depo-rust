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
use nu_ansi_term::Color::{Cyan, Red, Blue, Yellow};
use anyhow::Result;
use depo_api::{
    request::store_share::StoreShareExpression, DeleteAccountExpression, DeleteSharesExpression, FinishRecoveryExpression, GetRecoveryExpression, GetRecoveryResult, GetSharesExpression, GetSharesResult, Receipt, StartRecoveryExpression, StartRecoveryResult, StoreShareResult, UpdateKeyExpression, UpdateRecoveryExpression
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
    body: Expression,
    client_private_key: &PrivateKeyBase,
    depo_public_key: &PublicKeyBase,
    depo: &impl RequestHandler,
) -> SealedResponse {
    let id = ARID::new();
    let sender = client_private_key.public_key();
    let sealed_request = SealedRequest::new_with_body(body, id, sender);
    let encrypted_request = (sealed_request, client_private_key, depo_public_key).into();

    let raw_response = depo.handle_encrypted_request(encrypted_request).await;

    let sealed_response: SealedResponse = (raw_response, client_private_key).try_into().unwrap();
    sealed_response
    // if raw_response.is_failure() {
    //     return raw_response;
    // }
    // let response = raw_response.unseal(depo_public_key, client_private_key).unwrap();
    // assert_eq!(
    //     response.response_id().unwrap(),
    //     request.request_id().unwrap()
    // );
    // response
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
        info!("⚠️ {}", Yellow.paint($msg));
    };
}

pub async fn test_depo_scenario(depo_public_key: &PublicKeyBase, depo: &impl RequestHandler) {
    let alice_private_key = PrivateKeyBase::new();
    let alice_public_key = alice_private_key.public_key();

    let bob_private_key = PrivateKeyBase::new();
    let bob_public_key = bob_private_key.public_key();

    section!("Alice stores a share");
    let alice_data_1 = Bytes::from_static(&hex!("cafebabe"));
    let body = StoreShareExpression::new(alice_data_1.clone());
    let response: StoreShareResult = server_call(body.into(), &alice_private_key, depo_public_key, depo).await.try_into().unwrap();
    let alice_receipt_1 = response.receipt();

    section!("Bob stores a share");
    let bob_data_1 = Bytes::from_static(&hex!("deadbeef"));
    let body = StoreShareExpression::new(bob_data_1.clone());
    let response: StoreShareResult = server_call(body.into(), &bob_private_key, depo_public_key, depo).await.try_into().unwrap();
    let bob_receipt_1 = response.receipt();

    section!("Alice retrieves her share");
    let body = GetSharesExpression::new(vec![alice_receipt_1].into_iter().cloned().collect());
    let response: GetSharesResult = server_call(body.into(), &alice_private_key, depo_public_key, depo).await.try_into().unwrap();
    let alice_retrieved_data_1 = response.data_for_receipt(alice_receipt_1).unwrap();
    assert_eq!(alice_retrieved_data_1, &alice_data_1);

    section!("Bob retrieves his share");
    let body = GetSharesExpression::new(vec![bob_receipt_1].into_iter().cloned().collect());
    let response: GetSharesResult = server_call(body.into(), &bob_private_key, depo_public_key, depo).await.try_into().unwrap();
    let bob_retrieved_data_1 = response.data_for_receipt(bob_receipt_1).unwrap();
    assert_eq!(bob_retrieved_data_1, &bob_data_1);

    section!("Alice stores a second share");
    let alice_data_2 = Bytes::from_static(&hex!("cafef00d"));
    let body = StoreShareExpression::new(alice_data_2.clone());
    let response: StoreShareResult = server_call(body.into(), &alice_private_key, depo_public_key, depo).await.try_into().unwrap();
    let alice_receipt_2 = response.receipt();

    section!("Alice retrieves her second share");
    let body = GetSharesExpression::new(vec![alice_receipt_2].into_iter().cloned().collect());
    let response: GetSharesResult = server_call(body.into(), &alice_private_key, depo_public_key, depo).await.try_into().unwrap();
    let alice_retrieved_data_2 = response.data_for_receipt(alice_receipt_2).unwrap();
    assert_eq!(alice_retrieved_data_2, &alice_data_2);

//     section!("Alice retrieves both her shares identified only by her public key");
//     let request = GetSharesExpression::new(&alice_public_key, vec![]);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     let response = GetSharesResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.receipt_to_data().len(), 2);

//     section!("Bob attempts to retrieve one of Alice's shares");
//     let request = GetSharesExpression::new(&bob_public_key, vec![&alice_receipt_1]);
//     let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
//     let response = GetSharesResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.receipt_to_data().len(), 0);

//     alert!("Someone attempts to retrieve all shares from a nonexistent account");
//     let nonexistent_private_key = PrivateKeyBase::new();
//     let nonexistent_public_key = nonexistent_private_key.public_key();
//     let request = GetSharesExpression::new(&nonexistent_public_key, vec![]);
//     let response_envelope = server_call(request, &nonexistent_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

//     alert!("Someone attempts to retrieve all shares from Alice's account using her public key");
//     let request = GetSharesExpression::new(&alice_public_key, vec![]);
//     let response_envelope = server_call(request, &nonexistent_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("could not verify a signature"));

//     alert!("Alice attempts to retrieve her shares using the incorrect depo public key");
//     let request = GetSharesExpression::new(&alice_public_key, vec![]);
//     let response_envelope = server_call(request, &alice_private_key, &nonexistent_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("no recipient matches the given key"));

//     section!("Alice stores a share she's previously stored (idempotent)");
//     let request = StoreShareExpression::new(&alice_public_key, alice_data_1);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     let response = StoreShareResult::try_from(response_envelope).unwrap();
//     let alice_receipt_3 = response.receipt();
//     assert_eq!(alice_receipt_3, alice_receipt_1);

//     section!("Alice deletes one of her shares");
//     let request = DeleteSharesExpression::new(&alice_public_key, vec![&alice_receipt_1]);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     let request = GetSharesExpression::new(&alice_public_key, vec![]);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     let response = GetSharesResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.receipt_to_data().len(), 1);
//     let alice_retrieved_data_2 = response.data_for_receipt(&alice_receipt_2).unwrap();
//     assert_eq!(alice_retrieved_data_2, alice_data_2);

//     section!("Alice attempts to delete a share she already deleted (idempotent)");
//     let request = DeleteSharesExpression::new(&alice_public_key, vec![&alice_receipt_1]);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     let request = GetSharesExpression::new(&alice_public_key, vec![]);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     let response = GetSharesResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.receipt_to_data().len(), 1);
//     let alice_retrieved_data_2 = response.data_for_receipt(&alice_receipt_2).unwrap();
//     assert_eq!(alice_retrieved_data_2, alice_data_2);

//     section!("Bob adds a recovery method");
//     let bob_recovery = "bob@example.com";
//     let request = UpdateRecoveryExpression::new(&bob_public_key, Some(bob_recovery));
//     let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     section!("Bob sets the same recovery method again (idempotent)");
//     let request = UpdateRecoveryExpression::new(&bob_public_key, Some(bob_recovery));
//     let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     section!("Bob gets his recovery method");
//     let request = GetRecoveryExpression::new(&bob_public_key);
//     let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
//     let response = GetRecoveryResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.recovery(), Some(bob_recovery));

//     section!("Alice gets her recovery method, but she has none");
//     let request = GetRecoveryExpression::new(&alice_public_key);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     let response = GetRecoveryResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.recovery(), None);

//     alert!("Alice attempts to add a non-unique recovery method");
//     let request = UpdateRecoveryExpression::new(&alice_public_key, Some(bob_recovery));
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("recovery method already exists"));

//     alert!("Someone attempts to retrieve the recovery method for a nonexistent account");
//     let request = GetRecoveryExpression::new(&nonexistent_public_key);
//     let response_envelope = server_call(request, &nonexistent_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

//     section!("Alice updates her public key to a new one");
//     let alice_private_key_2 = PrivateKeyBase::new();
//     let alice_public_key_2 = alice_private_key_2.public_key();
//     let request = UpdateKeyExpression::new(&alice_public_key, &alice_public_key_2);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     alert!("Alice can no longer retrieve her shares using the old public key");
//     let request = GetSharesExpression::new(&alice_public_key, vec![]);
//     let response_envelope = server_call(request, &alice_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

//     section!("Alice must now use her new public key");
//     let request = GetSharesExpression::new(&alice_public_key_2, vec![]);
//     let response_envelope = server_call(request, &alice_private_key_2, depo_public_key, depo).await;
//     let response = GetSharesResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.receipt_to_data().len(), 1);

//     section!("Bob has lost his public key, so he wants to replace it with a new one");
//     let bob_private_key_2 = PrivateKeyBase::new();
//     let bob_public_key_2 = bob_private_key_2.public_key();

//     alert!("Bob requests transfer using an incorrect recovery method");
//     let incorrect_recovery = "wrong@example.com";
//     let request = StartRecoveryResult::new(&bob_public_key_2, incorrect_recovery);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown recovery"));

//     section!("Bob requests a transfer using the correct recovery method");
//     let request = StartRecoveryResult::new(&bob_public_key_2, bob_recovery);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     let response = StartRecoveryResult::try_from(response_envelope).unwrap();

//     // The recovery continuation is both signed by the server and encrypted to
//     // the server, and is also time-limited. It is sent to Bob's recovery
//     // contact method, which acts as a second factor. Once in possession of the
//     // recovery continuation, Bob can use it to finish the recovery process.
//     //
//     // For testing purposes only, we're allowed to skip the second factor and
//     // get the recovery continuation directly.
//     let continuation = response.continuation();

//     alert!("Bob attempts to use the recovery continuation to finish setting his new public key, but the request is signed by his old key");
//     let request = FinishRecoveryExpression::new(&bob_public_key, continuation.clone());
//     let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("invalid user signing key"));

//     section!("Bob uses the recovery continuation to finish setting his new public key, properly signed by his new key");
//     let request = FinishRecoveryExpression::new(&bob_public_key_2, continuation);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     alert!("Bob can no longer retrieve his shares using the old public key");
//     let request = GetSharesExpression::new(&bob_public_key, vec![]);
//     let response_envelope = server_call(request, &bob_private_key, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

//     section!("Bob must now use his new public key");
//     let request = GetSharesExpression::new(&bob_public_key_2, vec![]);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     let response = GetSharesResult::try_from(response_envelope).unwrap();
//     assert_eq!(response.receipt_to_data().len(), 1);

//     section!("Bob decides to delete his account");
//     let request = DeleteAccountExpression::new(&bob_public_key_2);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     alert!("Bob can no longer retrieve his shares using the new public key");
//     let request = GetSharesExpression::new(&bob_public_key_2, vec![]);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

//     alert!("Attempting to retrieve his recovery method now throws an error");
//     let request = GetRecoveryExpression::new(&bob_public_key_2);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.extract_error::<String>().unwrap().contains("unknown public key"));

//     section!("Deleting an account is idempotent");
//     let request = DeleteAccountExpression::new(&bob_public_key_2);
//     let response_envelope = server_call(request, &bob_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());

//     section!("Alice deletes her account");
//     let request = DeleteAccountExpression::new(&alice_public_key_2);
//     let response_envelope = server_call(request, &alice_private_key_2, depo_public_key, depo).await;
//     assert!(response_envelope.is_result_ok().unwrap());
}
