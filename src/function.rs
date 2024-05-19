use std::{collections::{HashMap, HashSet}, sync::Arc};

use anyhow::{bail, Result};
use bc_components::{PublicKeyBase, PrivateKeyBase};
use bc_envelope::prelude::*;
use bytes::Bytes;
use depo_api::{
    util::{Abbrev, FlankedFunction}, DeleteAccountExpression, DeleteSharesExpression, FinishRecoveryExpression, GetRecoveryExpression, GetSharesExpression, GetSharesResult, Receipt, StartRecoveryExpression, StartRecoveryResult, StoreShareExpression, StoreShareResult, UpdateKeyExpression, UpdateRecoveryExpression, DELETE_ACCOUNT_FUNCTION, DELETE_SHARES_FUNCTION, FINISH_RECOVERY_FUNCTION, GET_RECOVERY_FUNCTION, GET_SHARES_FUNCTION, START_RECOVERY_FUNCTION, STORE_SHARE_FUNCTION, UPDATE_KEY_FUNCTION, UPDATE_RECOVERY_FUNCTION
};
use log::{info, error};

use crate::{depo_impl::DepoImpl, record::Record, recovery_continuation::RecoveryContinuation};

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
                error!("unknown: invalid request");
                let sealed_response = SealedResponse::new_early_failure(self.public_key()).with_error("invalid request");
                let envelope: Envelope = (sealed_response, self.private_key()).into();
                return envelope.ur_string()
            }
        };
        self.handle_request(request_envelope).await.ur_string()
    }

    pub async fn handle_request(&self, encrypted_request: Envelope) -> Envelope {
        match self.handle_unverified_request(encrypted_request).await {
            Ok(success_response) => success_response,
            Err(e) => {
                let message = e.to_string();
                error!("unknown: {}", message);
                SealedResponse::new_early_failure(self.public_key())
                    .with_error(message)
                    .into()
            },
        }
    }

    pub async fn handle_unverified_request(&self, encrypted_request: Envelope) -> Result<Envelope> {
        let sealed_request: SealedRequest = (encrypted_request, self.private_key()).try_into()?;
        let id = sealed_request.id().clone();
        let function = sealed_request.function().clone();
        let sender = sealed_request.sender().clone();
        let sealed_response = match self.handle_verified_request(sealed_request).await {
            Ok(result) => {
                SealedResponse::new_success(id, self.public_key())
                    .with_result(result)
            },
            Err(e) => {
                let function_name = function.named_name().unwrap_or("unknown".to_string()).flanked_function();
                let message = format!("{}: {} {}", id, function_name, e);
                error!("{}", message);
                SealedResponse::new_failure(id, self.public_key())
                    .with_error(message)
            }
        };

        let sealed_envelope = (sealed_response, self.private_key(), &sender).into();
        Ok(sealed_envelope)
    }

    async fn handle_verified_request(&self, sealed_request: SealedRequest) -> Result<Envelope> {
        let function = sealed_request.function();
        let id = sealed_request.id();
        let sender = sealed_request.sender();
        let body = sealed_request.body().clone();

        info!("🔵 REQUEST {}:\n{}", id.abbrev(), body.envelope().format());

        let response = if function == &STORE_SHARE_FUNCTION {
            let expression: StoreShareExpression = body.try_into()?;
            let receipt = self.store_share(sender, expression.data()).await?;
            StoreShareResult::new(receipt).into()
        } else if function == &GET_SHARES_FUNCTION {
            let expression: GetSharesExpression = body.try_into()?;
            let receipt_to_data = self.get_shares(sender, expression.receipts()).await?;
            GetSharesResult::new(receipt_to_data).into()
        } else if function == &DELETE_SHARES_FUNCTION {
            let expression: DeleteSharesExpression = body.try_into()?;
            self.delete_shares(sender, expression.receipts()).await?;
            Envelope::ok()
        } else if function == &UPDATE_KEY_FUNCTION {
            let expression: UpdateKeyExpression = body.try_into()?;
            self.update_key(sender, expression.new_key()).await?;
            Envelope::ok()
        } else if function == &DELETE_ACCOUNT_FUNCTION {
            let _expression: DeleteAccountExpression = body.try_into()?;
            self.delete_account(sender).await?;
            Envelope::ok()
        } else if function == &UPDATE_RECOVERY_FUNCTION {
            let expression: UpdateRecoveryExpression = body.try_into()?;
            self.update_recovery(sender, expression.recovery().map(|x| x.as_str())).await?;
            Envelope::ok()
        } else if function == &GET_RECOVERY_FUNCTION {
            let _expression: GetRecoveryExpression = body.try_into()?;
            let recovery_method = self.get_recovery(sender).await?;
            Envelope::new_or_null(recovery_method)
        } else if function == &START_RECOVERY_FUNCTION {
            let expression: StartRecoveryExpression = body.try_into()?;
            let continuation = self.start_recovery(expression.recovery(), sender).await?;
            StartRecoveryResult::new(continuation).into()
        } else if function == &FINISH_RECOVERY_FUNCTION {
            let expression: FinishRecoveryExpression = body.try_into()?;
            self.finish_recovery(expression.continuation(), sender).await?;
            Envelope::ok()
        } else {
            bail!("unknown function: {}", function.name());
        };

        info!("✅ OK {}:\n{}", id.abbrev(), response.format());

        Ok(response)
    }
}

impl Depo {
    /// This is a Trust-On-First-Use (TOFU) function. If the provided public key is not
    /// recognized, then a new account is created and the provided data is stored in
    /// it. It is also used to add additional shares to an existing account. Adding an
    /// already existing share to an account is idempotent.
    pub async fn store_share(&self, key: &PublicKeyBase, data: &Bytes) -> Result<Receipt> {
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
    ) -> Result<HashMap<Receipt, Bytes>> {
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
    pub async fn get_share(&self, key: &PublicKeyBase, receipt: &Receipt) -> Result<Bytes> {
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
    ) -> Result<()> {
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
    pub async fn delete_share(&self, key: &PublicKeyBase, receipt: &Receipt) -> Result<()> {
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
    ) -> Result<()> {
        if self.0.existing_key_to_id(new_key).await?.is_some() {
            bail!("public key already in use");
        }
        self.0.set_user_key(old_key, new_key).await?;
        Ok(())
    }

    /// Deletes all the shares of an account and any other data associated with it, such
    /// as the recovery contact method. Deleting an account is idempotent; in other words,
    /// deleting a nonexistent account is not an error.
    pub async fn delete_account(&self, key: &PublicKeyBase) -> Result<()> {
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
    ) -> Result<()> {
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
    pub async fn get_recovery(&self, key: &PublicKeyBase) -> Result<Option<String>> {
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
    ) -> Result<Envelope> {
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
            .to_envelope()
            .seal(self.0.private_key(), self.public_key());
        Ok(continuation_envelope)
    }

    /// Completes a reset of the account's public key. This is called after the
    /// user has confirmed the change via their recovery contact method.
    pub async fn finish_recovery(&self, continuation_envelope: &Envelope, user_signing_key: &PublicKeyBase) -> Result<()> {
        let continuation: RecoveryContinuation = continuation_envelope
            .unseal(self.public_key(), self.0.private_key())?
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
