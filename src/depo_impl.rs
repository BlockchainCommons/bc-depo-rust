use std::collections::HashSet;

use anyhow::{bail, Result};
use async_trait::async_trait;
use bc_components::XID;
use bc_envelope::PrivateKeyBase;
use bc_xid::XIDDocument;
use depo_api::receipt::Receipt;

use crate::{user::User, record::Record};

#[async_trait]
pub trait DepoImpl {
    fn max_data_size(&self) -> u32;
    fn continuation_expiry_seconds(&self) -> u64;
    fn private_key(&self) -> &PrivateKeyBase;
    fn public_xid_document(&self) -> &XIDDocument;
    fn public_xid_document_string(&self) -> &str;
    async fn user_id_to_existing_user(&self, user_id: &XID) -> Result<Option<User>>;
    async fn insert_user(&self, user: &User) -> Result<()>;
    async fn insert_record(&self, record: &Record) -> Result<()>;
    async fn id_to_receipts(&self, user_id: &XID) -> Result<HashSet<Receipt>>;
    async fn receipt_to_record(&self, receipt: &Receipt) -> Result<Option<Record>>;
    async fn delete_record(&self, receipt: &Receipt) -> Result<()>;
    async fn set_user_xid_document(&self, user_id: &XID, new_xid_document: &XIDDocument) -> Result<()>;
    async fn set_user_recovery(&self, user: &User, recovery: Option<&str>) -> Result<()>;
    async fn remove_user(&self, user: &User) -> Result<()>;
    async fn recovery_to_user(&self, recovery: &str) -> Result<Option<User>>;

    async fn records_for_id_and_receipts(&self, user_id: &XID, recipts: &HashSet<Receipt>) -> Result<Vec<Record>> {
        let mut result = Vec::new();
        let user_receipts = self.id_to_receipts(user_id).await?;
        for receipt in recipts {
            if !user_receipts.contains(receipt) {
                continue;
            }
            if let Some(record) = self.receipt_to_record(receipt).await? {
                result.push(record.clone());
            }
        }
        Ok(result)
    }

    async fn xid_document_to_user(&self, xid_document: &XIDDocument) -> Result<User> {
        let maybe_user = self.user_id_to_existing_user(xid_document.xid()).await?;
        let user = match maybe_user {
            Some(user) => user,
            None => {
                let user = User::new(xid_document.clone());
                self.insert_user(&user).await?;
                user
            }
        };
        Ok(user)
    }

    async fn expect_user_id_to_user(&self, user_id: &XID) -> Result<User> {
        let user = match self.user_id_to_existing_user(user_id).await? {
            Some(user) => user,
            None => bail!("unknown user {}", user_id),
        };
        Ok(user)
    }
}
