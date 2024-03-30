use std::collections::HashSet;

use anyhow::bail;
use async_trait::async_trait;
use bc_components::{PrivateKeyBase, PublicKeyBase, ARID};
use depo_api::{receipt::Receipt, util::Abbrev};

use crate::record::Record;
use crate::user::User;

#[async_trait]
pub trait DepoImpl {
    fn max_data_size(&self) -> u32;
    fn continuation_expiry_seconds(&self) -> u32;
    fn private_key(&self) -> &PrivateKeyBase;
    fn public_key(&self) -> &PublicKeyBase;
    fn public_key_string(&self) -> &str;
    async fn existing_key_to_id(&self, key: &PublicKeyBase) -> anyhow::Result<Option<ARID>>;
    async fn existing_id_to_user(&self, user_id: &ARID) -> anyhow::Result<Option<User>>;
    async fn insert_user(&self, user: &User) -> anyhow::Result<()>;
    async fn insert_record(&self, record: &Record) -> anyhow::Result<()>;
    async fn id_to_receipts(&self, user_id: &ARID) -> anyhow::Result<HashSet<Receipt>>;
    async fn receipt_to_record(&self, receipt: &Receipt) -> anyhow::Result<Option<Record>>;
    async fn delete_record(&self, receipt: &Receipt) -> anyhow::Result<()>;
    async fn set_user_key(
        &self,
        old_key: &PublicKeyBase,
        new_key: &PublicKeyBase,
    ) -> anyhow::Result<()>;
    async fn set_user_recovery(&self, user: &User, recovery: Option<&str>) -> anyhow::Result<()>;
    async fn remove_user(&self, user: &User) -> anyhow::Result<()>;
    async fn recovery_to_user(&self, recovery: &str) -> anyhow::Result<Option<User>>;

    async fn records_for_id_and_receipts(
        &self,
        user_id: &ARID,
        recipts: &HashSet<Receipt>,
    ) -> anyhow::Result<Vec<Record>> {
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

    async fn existing_key_to_user(&self, key: &PublicKeyBase) -> anyhow::Result<Option<User>> {
        let user_id = self.existing_key_to_id(key).await?;
        let user = match user_id {
            Some(user_id) => self.existing_id_to_user(&user_id).await?,
            None => return Ok(None),
        };
        Ok(user)
    }

    async fn key_to_user(&self, key: &PublicKeyBase) -> anyhow::Result<User> {
        let user = self.existing_key_to_user(key).await?;
        let user = match user {
            Some(user_id) => user_id,
            None => {
                let user_id = ARID::new();
                let user = User::new(user_id.clone(), key.clone());
                self.insert_user(&user).await?;
                user
            }
        };
        Ok(user)
    }

    async fn expect_key_to_user(&self, key: &PublicKeyBase) -> anyhow::Result<User> {
        let user_id = self.existing_key_to_user(key).await?;
        let user_id = match user_id {
            Some(user_id) => user_id,
            None => bail!("unknown public key {}", key.abbrev()),
        };
        Ok(user_id)
    }
}
