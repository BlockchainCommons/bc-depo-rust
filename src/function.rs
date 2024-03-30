use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::bail;
use bc_components::{PrivateKeyBase, PublicKeyBase, ARID};
use bc_envelope::prelude::*;
use bytes::Bytes;
use depo_api::{
    util::{Abbrev, FlankedFunction},
    DeleteAccountRequest, DeleteAccountResponse, DeleteSharesRequest, DeleteSharesResponse,
    FinishRecoveryRequest, FinishRecoveryResponse, GetRecoveryRequest, GetRecoveryResponse,
    GetSharesRequest, GetSharesResponse, Receipt, StartRecoveryRequest, StartRecoveryResponse,
    StoreShareRequest, StoreShareResponse, UpdateKeyRequest, UpdateKeyResponse,
    UpdateRecoveryRequest, UpdateRecoveryResponse, DELETE_ACCOUNT_FUNCTION, DELETE_SHARES_FUNCTION,
    FINISH_RECOVERY_FUNCTION, GET_RECOVERY_FUNCTION, GET_SHARES_FUNCTION, KEY_PARAM,
    START_RECOVERY_FUNCTION, STORE_SHARE_FUNCTION, UPDATE_KEY_FUNCTION, UPDATE_RECOVERY_FUNCTION,
};
use log::{error, info};

use crate::{depo_impl::DepoImpl, record::Record};

use crate::recovery_continuation::RecoveryContinuation;

#[derive(Clone)]
pub struct Depo(Arc<dyn DepoImpl + Send + Sync>);

impl Depo {
    pub fn new(inner: Arc<dyn DepoImpl + Send + Sync>) -> Self {
        Self(inner)
    }

    pub fn private_key(&self) -> &PrivateKeyBase {
        self.0.private_key()
    }

    pub fn public_key(&self) -> &PublicKeyBase {
        self.0.public_key()
    }

    pub fn public_key_string(&self) -> &str {
        self.0.public_key_string()
    }

    pub async fn handle_request_string(&self, request: String) -> String {
        let request_envelope = match Envelope::from_ur_string(&request) {
            Ok(request) => request,
            Err(_) => {
                return new_error_response(None, None, "invalid request").ur_string();
            }
        };
        self.handle_request(request_envelope).await.ur_string()
    }

    pub async fn handle_request(&self, encrypted_request: Envelope) -> Envelope {
        match self.handle_unverified_request(encrypted_request).await {
            Ok(success_response) => success_response,
            Err(e) => new_error_response(None, None, e.to_string()),
        }
    }

    pub async fn handle_unverified_request(
        &self,
        encrypted_request: Envelope,
    ) -> anyhow::Result<Envelope> {
        let decrypted_request = encrypted_request
            .decrypt_to_recipient(self.0.private_key())
            .map_err(|_| anyhow::anyhow!("request not encrypted to depository public key"))?;
        let signed_request = decrypted_request.unwrap_envelope()?;

        // Verify that the key in the request is the same as the key used to sign the request
        let request = signed_request.unwrap_envelope()?;
        let body = request.request_body()?;
        let key: PublicKeyBase = body.extract_object_for_parameter(KEY_PARAM)?;
        let id = request.request_id()?;
        let function = body.function()?;
        signed_request
            .verify_signature_from(&key)
            .map_err(|_| anyhow::anyhow!("request signature does not match request key"))?;

        let unsigned_response = match self.handle_verified_request(body, request, &key).await {
            Ok(success_response) => success_response,
            Err(e) => {
                let function_name = function.named_name().unwrap_or("unknown".to_string());
                new_error_response(Some(&id), Some(&function_name), e.to_string())
            }
        };

        let signed_response = unsigned_response.sign_and_encrypt(self.0.private_key(), &key)?;
        Ok(signed_response)
    }

    async fn handle_verified_request(
        &self,
        body: Envelope,
        request: Envelope,
        user_signing_key: &PublicKeyBase,
    ) -> anyhow::Result<Envelope> {
        let function = &body.function()?;

        let response = if function == &STORE_SHARE_FUNCTION {
            self.handle_store_share(&request).await?
        } else if function == &GET_SHARES_FUNCTION {
            self.handle_get_shares(&request).await?
        } else if function == &DELETE_SHARES_FUNCTION {
            self.handle_delete_shares(&request).await?
        } else if function == &UPDATE_KEY_FUNCTION {
            self.handle_update_key(&request).await?
        } else if function == &DELETE_ACCOUNT_FUNCTION {
            self.handle_delete_account(&request).await?
        } else if function == &UPDATE_RECOVERY_FUNCTION {
            self.handle_update_recovery(&request).await?
        } else if function == &GET_RECOVERY_FUNCTION {
            self.handle_get_recovery(&request).await?
        } else if function == &START_RECOVERY_FUNCTION {
            self.handle_start_recovery(&request).await?
        } else if function == &FINISH_RECOVERY_FUNCTION {
            self.handle_finish_recovery(&request, user_signing_key)
                .await?
        } else {
            bail!("unknown function: {}", function.name());
        };

        Ok(response)
    }

    async fn handle_store_share(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = StoreShareRequest::from_envelope(request.clone())?;
        info!("{}", request);

        let receipt = self.store_share(request.key(), request.data()).await?;

        let response = StoreShareResponse::new(request.id().clone(), receipt);
        info!("{}", response);

        let response_envelope = response.clone().envelope();
        Ok(response_envelope)
    }

    async fn handle_get_shares(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = GetSharesRequest::from_envelope(request.clone())?;
        info!("{}", request);

        let receipt_to_data = self.get_shares(request.key(), request.receipts()).await?;

        let response = GetSharesResponse::new(request.id().clone(), receipt_to_data);
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_delete_shares(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = DeleteSharesRequest::from_envelope(request.clone())?;
        info!("{}", request);

        self.delete_shares(request.key(), request.receipts())
            .await?;

        let response = DeleteSharesResponse::new(request.id().clone());
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_update_key(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = UpdateKeyRequest::from_envelope(request.clone())?;
        info!("{}", request);

        self.update_key(request.key(), request.new_key()).await?;

        let response = UpdateKeyResponse::new(request.id().clone());
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_delete_account(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = DeleteAccountRequest::from_envelope(request.clone())?;
        info!("{}", request);

        self.delete_account(request.key()).await?;

        let response = DeleteAccountResponse::new(request.id().clone());
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_update_recovery(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = UpdateRecoveryRequest::from_envelope(request.clone())?;
        info!("{}", request);

        self.update_recovery(request.key(), request.recovery().map(|x| x.as_str()))
            .await?;

        let response = UpdateRecoveryResponse::new(request.id().clone());
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_get_recovery(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = GetRecoveryRequest::from_envelope(request.clone())?;
        info!("{}", request);

        let recovery_method = self.get_recovery(request.key()).await?;

        let response = GetRecoveryResponse::new(request.id().clone(), recovery_method);
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_start_recovery(&self, request: &Envelope) -> anyhow::Result<Envelope> {
        let request = StartRecoveryRequest::from_envelope(request.clone())?;
        info!("{}", request);

        let continuation = self
            .start_recovery(request.recovery(), request.key())
            .await?;

        let response = StartRecoveryResponse::new(request.id().clone(), continuation);
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }

    async fn handle_finish_recovery(
        &self,
        request: &Envelope,
        user_signing_key: &PublicKeyBase,
    ) -> anyhow::Result<Envelope> {
        let request = FinishRecoveryRequest::from_envelope(request.clone())?;
        info!("{}", request);

        self.finish_recovery(request.continuation(), user_signing_key)
            .await?;

        let response = FinishRecoveryResponse::new(request.id().clone());
        info!("{}", response);

        let response_envelope = response.into();
        Ok(response_envelope)
    }
}

impl Depo {
    /// This is a Trust-On-First-Use (TOFU) function. If the provided public key is not
    /// recognized, then a new account is created and the provided data is stored in
    /// it. It is also used to add additional shares to an existing account. Adding an
    /// already existing share to an account is idempotent.
    pub async fn store_share(&self, key: &PublicKeyBase, data: &Bytes) -> anyhow::Result<Receipt> {
        let user = self.0.key_to_user(key).await?;
        if data.len() > self.0.max_data_size() as usize {
            bail!("data too large");
        }
        let record = Record::new(user.user_id(), data);
        self.0.insert_record(&record).await?;
        Ok(record.receipt().clone())
    }

    /// Returns a dictionary of `[Receipt: Payload]` corresponding to the set of
    /// input receipts, or corresponding to all the controlled shares if no input
    /// receipts are provided. Attempting to retrieve nonexistent receipts or receipts
    /// from the wrong account is an error.
    pub async fn get_shares(
        &self,
        key: &PublicKeyBase,
        receipts: &HashSet<Receipt>,
    ) -> anyhow::Result<HashMap<Receipt, Bytes>> {
        let user = self.0.expect_key_to_user(key).await?;
        let receipts = if receipts.is_empty() {
            self.0.id_to_receipts(user.user_id()).await?
        } else {
            receipts.clone()
        };
        let records = self
            .0
            .records_for_id_and_receipts(user.user_id(), &receipts)
            .await?;
        let mut result = HashMap::new();
        for record in records {
            result.insert(record.receipt().clone(), record.data().clone());
        }
        Ok(result)
    }

    /// Returns a single share corresponding to the provided receipt. Attempting to
    /// retrieve a nonexistent receipt or a receipt from the wrong account is an error.
    pub async fn get_share(&self, key: &PublicKeyBase, receipt: &Receipt) -> anyhow::Result<Bytes> {
        let mut receipts = HashSet::new();
        receipts.insert(receipt.clone());
        let result = self.get_shares(key, &receipts).await?;
        let result = match result.get(receipt) {
            Some(result) => result.clone(),
            None => bail!("unknown receipt"),
        };
        Ok(result)
    }

    /// Deletes either a subset of shares a user controls, or all the shares if a
    /// subset of receipts is not provided. Deletes are idempotent; in other words,
    /// deleting nonexistent shares is not an error.
    pub async fn delete_shares(
        &self,
        key: &PublicKeyBase,
        receipts: &HashSet<Receipt>,
    ) -> anyhow::Result<()> {
        let user = self.0.expect_key_to_user(key).await?;
        let recpts = if receipts.is_empty() {
            self.0.id_to_receipts(user.user_id()).await?
        } else {
            receipts.clone()
        };
        for receipt in recpts {
            if self.0.receipt_to_record(&receipt).await?.is_some() {
                self.0.delete_record(&receipt).await?;
            }
        }
        Ok(())
    }

    /// Deletes a single share a user controls. Deletes are idempotent; in other words,
    /// deleting a nonexistent share is not an error.
    pub async fn delete_share(&self, key: &PublicKeyBase, receipt: &Receipt) -> anyhow::Result<()> {
        let mut receipts = HashSet::new();
        receipts.insert(receipt.clone());
        self.delete_shares(key, &receipts).await?;
        Ok(())
    }

    /// Changes the public key used as the account identifier. It could be invoked
    /// specifically because a user requests it, in which case they will need to know
    /// their old public key, or it could be invoked because they used their recovery
    /// contact method to request a transfer token that encodes their old public key.
    pub async fn update_key(
        &self,
        old_key: &PublicKeyBase,
        new_key: &PublicKeyBase,
    ) -> anyhow::Result<()> {
        if self.0.existing_key_to_id(new_key).await?.is_some() {
            bail!("public key already in use");
        }
        self.0.set_user_key(old_key, new_key).await?;
        Ok(())
    }

    /// Deletes all the shares of an account and any other data associated with it, such
    /// as the recovery contact method. Deleting an account is idempotent; in other words,
    /// deleting a nonexistent account is not an error.
    pub async fn delete_account(&self, key: &PublicKeyBase) -> anyhow::Result<()> {
        if let Some(user) = self.0.existing_key_to_user(key).await? {
            self.delete_shares(key, &HashSet::new()).await?;
            self.0.remove_user(&user).await?;
        }
        Ok(())
    }

    /// Updates an account's recovery contact method, which could be a phone
    /// number, email address, or similar.
    ///
    /// The recovery contact method is used to give users a way to change their
    /// public key in the event they lose it. It is up to the implementer to
    /// validate the recovery contact method before letting the public key be
    /// changed.
    ///
    /// The recovery method must be unique within the depository because it is
    /// used to identify the account when resetting the public key.
    ///
    /// If `recovery` is `None`, then the recovery contact method is deleted.
    pub async fn update_recovery(
        &self,
        key: &PublicKeyBase,
        recovery: Option<&str>,
    ) -> anyhow::Result<()> {
        let user = self.0.expect_key_to_user(key).await?;
        // Recovery methods must be unique
        if let Some(non_opt_recovery) = recovery {
            let existing_recovery_user = self.0.recovery_to_user(non_opt_recovery).await?;
            if let Some(existing_recovery_user) = existing_recovery_user {
                if existing_recovery_user.user_id() != user.user_id() {
                    bail!("recovery method already exists");
                } else {
                    // The user is already using this recovery, so we can just return
                    // (idempotency)
                    return Ok(());
                }
            }
        }
        self.0.set_user_recovery(&user, recovery).await?;
        Ok(())
    }

    /// Retrieves an account's recovery contact method, if any.
    pub async fn get_recovery(&self, key: &PublicKeyBase) -> anyhow::Result<Option<String>> {
        let user = self.0.expect_key_to_user(key).await?;
        let recovery = user.recovery().map(|s| s.to_string());
        Ok(recovery)
    }

    /// Requests a reset of the account's public key without knowing the current
    /// one. The account must have a validated recovery contact method that
    /// matches the one provided. The depository owner needs to then contact the
    /// user via their recovery contact method to confirm the change. If the
    /// request is not confirmed and the continuation used by a set amount of
    /// time, then the change is not made.
    ///
    /// Recovery methods must be unique. Examples of possible recovery methods
    /// include some sort of username, real name, or other unique identifier,
    /// paired with an email addresses, phone number, list of security
    /// questions, two-factor authentication key for time-based one-time
    /// passwords, list of trusted devices for 2FA, or similar.
    ///
    /// Returns a continuation, which is a token that can be used to complete
    /// the reset.
    pub async fn start_recovery(
        &self,
        recovery: impl AsRef<str>,
        new_key: &PublicKeyBase,
    ) -> anyhow::Result<Envelope> {
        // First find the user for the recovery.
        let user = self.0.recovery_to_user(recovery.as_ref()).await?;
        // If no recovery was found return an error.
        let user = match user {
            Some(user) => user,
            None => bail!("unknown recovery"),
        };
        // Ensure there is no account with the new public key
        let existing_user = self.0.existing_key_to_id(new_key).await?;
        if existing_user.is_some() {
            bail!("public key already in use");
        }
        let recovery_continuation = RecoveryContinuation::new(
            user.public_key().clone(),
            new_key.clone(),
            dcbor::Date::now() + self.0.continuation_expiry_seconds() as f64,
        );
        let continuation_envelope = recovery_continuation
            .envelope()
            .sign_and_encrypt(self.0.private_key(), self.0.public_key())?;
        Ok(continuation_envelope)
    }

    /// Completes a reset of the account's public key. This is called after the
    /// user has confirmed the change via their recovery contact method.
    pub async fn finish_recovery(
        &self,
        continuation_envelope: &Envelope,
        user_signing_key: &PublicKeyBase,
    ) -> anyhow::Result<()> {
        let continuation: RecoveryContinuation = continuation_envelope
            .verify_and_decrypt(self.0.public_key(), self.0.private_key())?
            .try_into()?;
        // Ensure the continuation is valid
        let seconds_until_expiry = continuation.expiry().clone() - dcbor::Date::now();
        if seconds_until_expiry < 0.0 {
            bail!("continuation expired");
        }

        // Ensure the user's public key used to sign the request matches the new public key in the continuation
        if continuation.new_key() != user_signing_key {
            bail!("invalid user signing key");
        }

        // Ensure the recovery has been verified.

        // Set the user's public key to the new public key
        self.0
            .set_user_key(continuation.old_key(), continuation.new_key())
            .await?;
        Ok(())
    }
}

fn new_error_response(
    response_id: Option<&ARID>,
    function: Option<&str>,
    error: impl AsRef<str>,
) -> Envelope {
    let function_string = match function {
        Some(function) => function.to_string(),
        None => "unknown".to_string(),
    }
    .flanked_function();
    let message = format!("{} {}", function_string, error.as_ref());
    let id_string = response_id
        .map(|id| id.abbrev())
        .unwrap_or_else(|| "unknown   ".to_string());
    error!("{}: {}", id_string, message);
    Envelope::new_error_response(response_id, Some(message))
}
