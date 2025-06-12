use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, bail};
use bc_components::{PrivateKeys, XIDProvider};
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use dcbor::Date;
use depo_api::{
    DELETE_ACCOUNT_FUNCTION, DELETE_SHARES_FUNCTION, DeleteAccount,
    DeleteShares, FINISH_RECOVERY_FUNCTION, FinishRecovery,
    GET_RECOVERY_FUNCTION, GET_SHARES_FUNCTION, GetRecovery, GetShares,
    GetSharesResult, Receipt, START_RECOVERY_FUNCTION, STORE_SHARE_FUNCTION,
    StartRecovery, StoreShare, StoreShareResult, UPDATE_RECOVERY_FUNCTION,
    UPDATE_XID_DOCUMENT_FUNCTION, UpdateRecovery, UpdateXIDDocument,
    util::{Abbrev, FlankedFunction},
};
use gstp::prelude::*;
use log::{error, info};

use crate::{
    depo_impl::DepoImpl, record::Record,
    recovery_continuation::RecoveryContinuation,
};

#[derive(Clone)]
pub struct Depo(Arc<dyn DepoImpl + Send + Sync>);

impl Depo {
    pub fn new(inner: Arc<dyn DepoImpl + Send + Sync>) -> Self { Self(inner) }

    pub fn private_keys(&self) -> &PrivateKeys { self.0.private_keys() }

    pub fn public_xid_document(&self) -> &XIDDocument {
        self.0.public_xid_document()
    }

    pub fn public_xid_document_string(&self) -> &str {
        self.0.public_xid_document_string()
    }
}

impl Depo {
    pub async fn handle_request_string(&self, ur_string: String) -> String {
        match Envelope::from_ur_string(&ur_string) {
            Ok(request_envelope) => {
                self.handle_request(request_envelope).await.ur_string()
            }
            Err(_) => {
                error!("unknown: invalid request");
                let sealed_response = SealedResponse::new_early_failure(
                    self.public_xid_document(),
                )
                .with_error("invalid request");
                sealed_response
                    .to_envelope(None, Some(self.private_keys()), None)
                    .unwrap()
                    .ur_string()
            }
        }
    }

    pub async fn handle_request(
        &self,
        encrypted_request: Envelope,
    ) -> Envelope {
        match self.handle_unverified_request(encrypted_request).await {
            Ok(success_response) => success_response,
            Err(error) => {
                let message = error.to_string();
                error!("unknown: {}", message);
                SealedResponse::new_early_failure(self.public_xid_document())
                    .with_error(message)
                    .to_envelope(None, None, None)
                    .unwrap()
            }
        }
    }

    pub async fn handle_unverified_request(
        &self,
        encrypted_request: Envelope,
    ) -> Result<Envelope> {
        let sealed_request = SealedRequest::try_from_envelope(
            &encrypted_request,
            None,
            None,
            self.private_keys(),
        )?;
        let id = sealed_request.id();
        let function = sealed_request.function().clone();
        let sender = sealed_request.sender().clone();
        let peer_continuation = sealed_request.peer_continuation().cloned();
        let sealed_response =
            match self.handle_verified_request(sealed_request).await {
                Ok((result, state)) => {
                    SealedResponse::new_success(id, self.public_xid_document())
                        .with_result(result)
                        .with_optional_state(state)
                        .with_peer_continuation(peer_continuation.as_ref())
                }
                Err(error) => {
                    let function_name = function
                        .named_name()
                        .unwrap_or("unknown".to_string())
                        .flanked_function();
                    let message =
                        format!("{}: {} {}", id.abbrev(), function_name, error);
                    error!("{}", message);
                    SealedResponse::new_failure(id, self.public_xid_document())
                        .with_error(message)
                        .with_peer_continuation(peer_continuation.as_ref())
                }
            };

        let state_expiry_date = Date::now()
            + Duration::from_secs(self.0.continuation_expiry_seconds());
        let sealed_envelope = sealed_response
            .to_envelope(
                Some(&state_expiry_date),
                Some(self.private_keys()),
                Some(&sender),
            )
            .unwrap();
        Ok(sealed_envelope)
    }

    async fn validate_sender_key(&self, sender: &XIDDocument) -> Result<()> {
        let user_id = sender.xid();
        let user = self.0.expect_user_id_to_user(user_id).await?;
        if user.xid_document().verification_key() != sender.verification_key() {
            bail!("invalid sender verification key for {user_id}");
        }
        Ok(())
    }

    async fn handle_verified_request(
        &self,
        sealed_request: SealedRequest,
    ) -> Result<(Envelope, Option<Envelope>)> {
        let function = sealed_request.function();
        let id = sealed_request.id();
        let sender = sealed_request.sender();
        let body = sealed_request.body().clone();

        info!(
            "🔵 REQUEST {}:\n{}",
            id.abbrev(),
            body.expression_envelope().format()
        );

        let (response, state) = if function == &STORE_SHARE_FUNCTION {
            let expression = StoreShare::try_from(body)?;
            let receipt = self.store_share(sender, expression.data()).await?;
            (StoreShareResult::new(receipt).into(), None)
        } else if function == &GET_SHARES_FUNCTION {
            let expression = GetShares::try_from(body)?;
            let receipt_to_data =
                self.get_shares(sender, expression.receipts()).await?;
            (GetSharesResult::new(receipt_to_data).into(), None)
        } else if function == &DELETE_SHARES_FUNCTION {
            let expression = DeleteShares::try_from(body)?;
            self.delete_shares(sender, expression.receipts()).await?;
            (Envelope::ok(), None)
        } else if function == &UPDATE_XID_DOCUMENT_FUNCTION {
            let expression = UpdateXIDDocument::try_from(body)?;
            self.update_xid_document(sender, expression.new_xid_document())
                .await?;
            (Envelope::ok(), None)
        } else if function == &DELETE_ACCOUNT_FUNCTION {
            let _expression = DeleteAccount::try_from(body)?;
            self.delete_account(sender).await?;
            (Envelope::ok(), None)
        } else if function == &UPDATE_RECOVERY_FUNCTION {
            let expression = UpdateRecovery::try_from(body)?;
            self.update_recovery(
                sender,
                expression.recovery().map(|x| x.as_str()),
            )
            .await?;
            (Envelope::ok(), None)
        } else if function == &GET_RECOVERY_FUNCTION {
            let _expression = GetRecovery::try_from(body)?;
            let recovery_method = self.get_recovery(sender).await?;
            (Envelope::new_or_null(recovery_method), None)
        } else if function == &START_RECOVERY_FUNCTION {
            let expression = StartRecovery::try_from(body)?;
            let continuation =
                self.start_recovery(expression.recovery(), sender).await?;
            (Envelope::ok(), Some(continuation))
        } else if function == &FINISH_RECOVERY_FUNCTION {
            let _expression = FinishRecovery::try_from(body)?;
            if let Some(state) = sealed_request.state() {
                self.finish_recovery(state, sender).await?;
            } else {
                bail!("missing state");
            }
            // self.finish_recovery(expression.continuation(), sender).await?;
            (Envelope::ok(), None)
        } else {
            bail!("unknown function: {}", function.name());
        };

        info!("✅ OK {}:\n{}", id.abbrev(), response.format());

        Ok((response, state))
    }
}

impl Depo {
    /// This is a Trust-On-First-Use (TOFU) function. If the provided XID is not
    /// recognized, then a new account is created and the provided data is
    /// stored in it. This function is also used to add additional shares to an
    /// existing account. Adding an already existing share to an account is
    /// idempotent.
    pub async fn store_share(
        &self,
        sender: &XIDDocument,
        data: impl Into<ByteString>,
    ) -> Result<Receipt> {
        let user = self.0.xid_document_to_user(sender).await?;
        let data: ByteString = data.into();
        if data.len() > self.0.max_data_size() as usize {
            bail!("data too large");
        }
        let record = Record::new(user.user_id(), data);
        self.0.insert_record(&record).await?;
        Ok(record.receipt().clone())
    }

    /// Returns a dictionary of `[Receipt: Payload]` corresponding to the set of
    /// input receipts, or corresponding to all the controlled shares if no
    /// input receipts are provided. Attempting to retrieve nonexistent
    /// receipts or receipts from the wrong account is an error.
    pub async fn get_shares(
        &self,
        sender: &XIDDocument,
        receipts: &HashSet<Receipt>,
    ) -> Result<HashMap<Receipt, ByteString>> {
        self.validate_sender_key(sender).await?;
        let user_id = sender.xid();
        let user = self.0.expect_user_id_to_user(user_id).await?;
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

    /// Returns a single share corresponding to the provided receipt. Attempting
    /// to retrieve a nonexistent receipt or a receipt from the wrong
    /// account is an error.
    pub async fn get_share(
        &self,
        sender: &XIDDocument,
        receipt: &Receipt,
    ) -> Result<ByteString> {
        self.validate_sender_key(sender).await?;
        let mut receipts = HashSet::new();
        receipts.insert(receipt.clone());
        let result = self.get_shares(sender, &receipts).await?;
        let result = match result.get(receipt) {
            Some(result) => result.clone(),
            None => bail!("unknown receipt"),
        };
        Ok(result)
    }

    /// Deletes either a subset of shares a user controls, or all the shares if
    /// a subset of receipts is not provided. Deletes are idempotent; in
    /// other words, deleting nonexistent shares is not an error.
    pub async fn delete_shares(
        &self,
        sender: &XIDDocument,
        receipts: &HashSet<Receipt>,
    ) -> Result<()> {
        self.validate_sender_key(sender).await?;
        let user_id = sender.xid();
        let user = self.0.expect_user_id_to_user(user_id).await?;
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

    /// Deletes a single share a user controls. Deletes are idempotent; in other
    /// words, deleting a nonexistent share is not an error.
    pub async fn delete_share(
        &self,
        sender: &XIDDocument,
        receipt: &Receipt,
    ) -> Result<()> {
        self.validate_sender_key(sender).await?;
        let mut receipts = HashSet::new();
        receipts.insert(receipt.clone());
        self.delete_shares(sender, &receipts).await?;
        Ok(())
    }

    /// Changes the public key used as the account identifier. It could be
    /// invoked specifically because a user requests it, in which case they
    /// will need to know their old public key, or it could be invoked
    /// because they used their recovery contact method to request a
    /// transfer token that encodes their old public key.
    pub async fn update_xid_document(
        &self,
        sender: &XIDDocument,
        new_xid_document: &XIDDocument,
    ) -> Result<()> {
        self.validate_sender_key(sender).await?;
        let user_id = sender.xid();
        self.0
            .set_user_xid_document(user_id, new_xid_document)
            .await?;
        Ok(())
    }

    /// Deletes all the shares of an account and any other data associated with
    /// it, such as the recovery contact method. Deleting an account is
    /// idempotent; in other words, deleting a nonexistent account is not an
    /// error.
    pub async fn delete_account(&self, sender: &XIDDocument) -> Result<()> {
        let user_id = sender.xid();
        if let Some(user) = self.0.user_id_to_existing_user(user_id).await? {
            self.validate_sender_key(sender).await?;
            self.delete_shares(sender, &HashSet::new()).await?;
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
        sender: &XIDDocument,
        recovery: Option<&str>,
    ) -> Result<()> {
        self.validate_sender_key(sender).await?;
        let user_id = sender.xid();
        let user = self.0.expect_user_id_to_user(user_id).await?;
        // Recovery methods must be unique
        if let Some(non_opt_recovery) = recovery {
            let existing_recovery_user =
                self.0.recovery_to_user(non_opt_recovery).await?;
            if let Some(existing_recovery_user) = existing_recovery_user {
                if existing_recovery_user.user_id() != user.user_id() {
                    bail!("recovery method already exists");
                } else {
                    // The user is already using this recovery, so we can just
                    // return (idempotency)
                    return Ok(());
                }
            }
        }
        self.0.set_user_recovery(&user, recovery).await?;
        Ok(())
    }

    /// Retrieves an account's recovery contact method, if any.
    pub async fn get_recovery(
        &self,
        sender: &XIDDocument,
    ) -> Result<Option<String>> {
        self.validate_sender_key(sender).await?;
        let user_id = sender.xid();
        let user = self.0.expect_user_id_to_user(user_id).await?;
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
        new_xid_document: &XIDDocument,
    ) -> Result<Envelope> {
        // First find the user for the recovery.
        let user = self.0.recovery_to_user(recovery.as_ref()).await?;
        // If no recovery was found return an error.
        let user = match user {
            Some(user) => user,
            None => bail!("unknown recovery"),
        };
        let recovery_continuation = RecoveryContinuation::new(
            user.user_id(),
            new_xid_document.clone(),
            dcbor::Date::now() + self.0.continuation_expiry_seconds() as f64,
        );
        let continuation_envelope = recovery_continuation.to_envelope();
        Ok(continuation_envelope)
    }

    /// Completes a reset of the account's public key. This is called after the
    /// user has confirmed the change via their recovery contact method.
    pub async fn finish_recovery(
        &self,
        continuation_envelope: &Envelope,
        sender: &XIDDocument,
    ) -> Result<()> {
        let continuation =
            RecoveryContinuation::try_from(continuation_envelope.clone())?;
        // Ensure the continuation is valid
        let seconds_until_expiry =
            continuation.expiry().clone() - dcbor::Date::now();
        if seconds_until_expiry < 0.0 {
            bail!("continuation expired");
        }

        // Ensure the user's public key used to sign the request matches the new
        // public key in the continuation
        if continuation.new_xid_document().verification_key()
            != sender.verification_key()
        {
            bail!("incorrect verification key");
        }

        // Ensure the recovery has been verified.

        // Set the user's public key to the new public key
        self.0
            .set_user_xid_document(
                continuation.user_id(),
                continuation.new_xid_document(),
            )
            .await?;
        Ok(())
    }
}
