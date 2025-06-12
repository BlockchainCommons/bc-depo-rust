use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::Result;
use async_trait::async_trait;
use bc_components::{PrivateKeys, XID, keypair};
use bc_envelope::prelude::*;
use bc_xid::XIDDocument;
use depo_api::receipt::Receipt;
use tokio::sync::RwLock;

use crate::{
    CONTINUATION_EXPIRY_SECONDS, MAX_DATA_SIZE, depo_impl::DepoImpl,
    function::Depo, record::Record, user::User,
};

struct Inner {
    id_to_user: HashMap<XID, User>,
    recovery_to_id: HashMap<String, XID>,
    receipt_to_record: HashMap<Receipt, Record>,
    id_to_receipts: HashMap<XID, HashSet<Receipt>>,
}

struct MemDepoImpl {
    private_keys: PrivateKeys,
    public_xid_document: XIDDocument,
    public_xid_document_string: String,
    inner: RwLock<Inner>,
}

impl MemDepoImpl {
    fn new() -> Arc<Self> {
        let (private_keys, public_keys) = keypair();
        let public_xid_document = XIDDocument::from(public_keys);
        let public_xid_document_string = public_xid_document.ur_string();
        Arc::new(Self {
            private_keys,
            public_xid_document,
            public_xid_document_string,
            inner: RwLock::new(Inner {
                id_to_user: HashMap::new(),
                recovery_to_id: HashMap::new(),
                receipt_to_record: HashMap::new(),
                id_to_receipts: HashMap::new(),
            }),
        })
    }
}

impl std::fmt::Debug for MemDepoImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.inner.try_read() {
            Ok(read) => {
                write!(
                    f,
                    "MemStore(users_by_id: {:?}, records_by_receipt: {:?}), receipts_by_user_id: {:?}",
                    read.id_to_user,
                    read.receipt_to_record,
                    read.id_to_receipts,
                )
            }
            Err(_) => write!(f, "MemStore: <locked>"),
        }
    }
}

#[async_trait]
impl DepoImpl for MemDepoImpl {
    fn max_data_size(&self) -> u32 { MAX_DATA_SIZE }

    fn continuation_expiry_seconds(&self) -> u64 { CONTINUATION_EXPIRY_SECONDS }

    fn private_keys(&self) -> &PrivateKeys { &self.private_keys }

    fn public_xid_document(&self) -> &XIDDocument { &self.public_xid_document }

    fn public_xid_document_string(&self) -> &str {
        &self.public_xid_document_string
    }

    async fn user_id_to_existing_user(
        &self,
        user_id: XID,
    ) -> Result<Option<User>> {
        Ok(self.inner.read().await.id_to_user.get(&user_id).cloned())
    }

    async fn insert_user(&self, user: &User) -> Result<()> {
        let mut write = self.inner.write().await;
        write.id_to_user.insert(user.user_id(), user.clone());
        write.id_to_receipts.insert(user.user_id(), HashSet::new());
        Ok(())
    }

    async fn insert_record(&self, record: &Record) -> Result<()> {
        let mut write = self.inner.write().await;
        let receipt = record.receipt();
        write
            .receipt_to_record
            .insert(receipt.clone(), record.clone());
        write
            .id_to_receipts
            .get_mut(&record.user_id())
            .unwrap()
            .insert(receipt.clone());
        Ok(())
    }

    async fn id_to_receipts(&self, user_id: XID) -> Result<HashSet<Receipt>> {
        Ok(self
            .inner
            .read()
            .await
            .id_to_receipts
            .get(&user_id)
            .unwrap()
            .clone())
    }

    async fn receipt_to_record(
        &self,
        receipt: &Receipt,
    ) -> Result<Option<Record>> {
        let read = self.inner.read().await;
        let record = read.receipt_to_record.get(receipt);
        Ok(record.cloned())
    }

    async fn delete_record(&self, receipt: &Receipt) -> Result<()> {
        let record = self.receipt_to_record(receipt).await?;
        if let Some(record) = record {
            let mut write = self.inner.write().await;
            write.receipt_to_record.remove(receipt);
            write
                .id_to_receipts
                .get_mut(&record.user_id())
                .unwrap()
                .remove(receipt);
        }
        Ok(())
    }

    async fn set_user_xid_document(
        &self,
        user_id: XID,
        new_xid_document: &XIDDocument,
    ) -> Result<()> {
        let user = self.expect_user_id_to_user(user_id).await?;
        let mut write = self.inner.write().await;
        let user = write.id_to_user.get_mut(&user.user_id()).unwrap();
        user.set_xid_document(new_xid_document);
        Ok(())
    }

    async fn set_user_recovery(
        &self,
        user: &User,
        recovery: Option<&str>,
    ) -> Result<()> {
        let mut write = self.inner.write().await;

        // get the user's existing recovery
        let old_recovery = user.recovery();
        // if the new and old recoverys are the same, return (idempotency)
        if old_recovery == recovery {
            return Ok(());
        }
        // Remove the old recovery, if any
        if let Some(old_recovery) = old_recovery {
            write.recovery_to_id.remove(old_recovery);
        }
        // Add the new recovery, if any
        if let Some(recovery) = recovery {
            write
                .recovery_to_id
                .insert(recovery.to_string(), user.user_id());
        }
        // Set the user record to the new recovery
        let user = write.id_to_user.get_mut(&user.user_id()).unwrap();
        user.set_recovery(recovery);
        Ok(())
    }

    async fn remove_user(&self, user: &User) -> Result<()> {
        let mut write = self.inner.write().await;

        write
            .recovery_to_id
            .remove(user.recovery().unwrap_or_default());
        write.id_to_user.remove(&user.user_id());
        write.id_to_receipts.remove(&user.user_id());
        Ok(())
    }

    async fn recovery_to_user(&self, recovery: &str) -> Result<Option<User>> {
        let read = self.inner.read().await;
        let user_id = read.recovery_to_id.get(recovery).cloned();
        let user = if let Some(user_id) = user_id {
            self.user_id_to_existing_user(user_id).await?
        } else {
            None
        };
        Ok(user)
    }
}

impl Depo {
    pub fn new_in_memory() -> Self { Self::new(MemDepoImpl::new()) }
}
