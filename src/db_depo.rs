use std::{collections::HashSet, sync::Arc};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bc_components::{keypair, PrivateKeys, XID};
use bc_envelope::{prelude::*, PublicKeys};
use bc_xid::XIDDocument;
use depo_api::receipt::Receipt;
use mysql_async::{prelude::*, Pool, Row};
use url::Url;

use crate::{
    depo_impl::DepoImpl, function::Depo, record::Record, user::User,
    CONTINUATION_EXPIRY_SECONDS, MAX_DATA_SIZE,
};

const USER: &str = "root";
const PASSWORD: Option<&str> = None;
const HOST: &str = "localhost";
const PORT: u16 = 3306;

const USERS_TABLE_NAME: &str = "users";
const RECORDS_TABLE_NAME: &str = "records";
const SETTINGS_TABLE_NAME: &str = "settings";

struct DbDepoImpl {
    schema_name: String,
    pool: Pool,
    private_keys: PrivateKeys,
    public_xid_document: XIDDocument,
    public_xid_document_string: String,
    continuation_expiry_seconds: u64,
    max_data_size: u32,
}

impl DbDepoImpl {
    async fn new(schema_name: impl AsRef<str>) -> Result<Arc<Self>> {
        let schema_name = schema_name.as_ref().to_string();
        let pool = db_pool(&schema_name);
        let (private_keys, public_keys, continuation_expiry_seconds, max_data_size) =
            get_settings(&pool, &schema_name).await?;
        let public_xid_document = XIDDocument::from(public_keys);
        let public_xid_document_string = public_xid_document.ur_string();
        Ok(Arc::new(Self {
            schema_name,
            pool,
            private_keys,
            public_xid_document,
            public_xid_document_string,
            continuation_expiry_seconds,
            max_data_size,
        }))
    }

    fn schema_name(&self) -> &str {
        &self.schema_name
    }
}

async fn get_settings(
    pool: &Pool,
    schema_name: &str,
) -> Result<(PrivateKeys, PublicKeys, u64, u32)> {
    let mut conn = pool.get_conn().await?;
    let query = format!(r"
        SELECT private_keys, public_keys, continuation_expiry_seconds, max_data_size
        FROM {schema_name}.{SETTINGS_TABLE_NAME}
    ");

    let result: Option<Row> = conn.query_first(query).await?;
    match result {
        Some(row) => {
            let private_keys_string: String = row
                .get("private_keys")
                .ok_or_else(|| anyhow!("Private keys not found"))?;
            let private_keys = PrivateKeys::from_ur_string(private_keys_string)?;
            let public_keys_string: String = row
                .get("public_keys")
                .ok_or_else(|| anyhow!("Public keys not found"))?;
            let public_keys = PublicKeys::from_ur_string(public_keys_string)?;
            let continuation_expiry_seconds: u64 = row
                .get("continuation_expiry_seconds")
                .ok_or_else(|| anyhow!("Continuation expiry seconds not found"))?;
            let max_data_size: u32 = row
                .get("max_data_size")
                .ok_or_else(|| anyhow!("Max payload size not found"))?;

            Ok((private_keys, public_keys, continuation_expiry_seconds, max_data_size))
        }
        None => Err(anyhow!("Settings not found")),
    }
}

#[async_trait]
impl DepoImpl for DbDepoImpl {
    fn max_data_size(&self) -> u32 {
        self.max_data_size
    }

    fn continuation_expiry_seconds(&self) -> u64 {
        self.continuation_expiry_seconds
    }

    fn private_keys(&self) -> &PrivateKeys {
        &self.private_keys
    }

    fn public_xid_document(&self) -> &XIDDocument {
        &self.public_xid_document
    }

    fn public_xid_document_string(&self) -> &str {
        &self.public_xid_document_string
    }

    async fn user_id_to_existing_user(&self, user_id: XID) -> Result<Option<User>> {
        let mut conn = self.pool.get_conn().await?;
        let query = "SELECT user_id, xid_document, recovery FROM users WHERE user_id = :user_id";
        let params = params! {
            "user_id" => user_id.ur_string()
        };

        let result: Option<Row> = conn.exec_first(query, params).await?;
        if let Some(row) = result {
            Ok(Some(row_to_user(row)))
        } else {
            Ok(None)
        }
    }

    async fn insert_user(&self, user: &User) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let schema_name = self.schema_name();
        let query = format!(r"
            INSERT INTO {schema_name}.{USERS_TABLE_NAME}
            (user_id, xid_document, recovery)
            VALUES (:user_id, :xid_document, :recovery)
        ");
        let params = params! {
            "user_id" => user.user_id().ur_string(),
            "xid_document" => user.xid_document().ur_string(),
            "recovery" => user.recovery(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn insert_record(&self, record: &Record) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let schema_name = self.schema_name();
        let query = format!(r"
            INSERT IGNORE INTO {schema_name}.{RECORDS_TABLE_NAME}
            (receipt, user_id, data)
            VALUES (:receipt, :user_id, :data)
        ");
        let params = params! {
            "receipt" => record.receipt().to_envelope().ur_string(),
            "user_id" => record.user_id().ur_string(),
            "data" => record.data().as_ref(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn id_to_receipts(&self, user_id: XID) -> Result<HashSet<Receipt>> {
        let mut conn = self.pool.get_conn().await?;
        let schema_name = self.schema_name();
        let query = format!(r"
            SELECT receipt
            FROM {schema_name}.{RECORDS_TABLE_NAME}
            WHERE user_id = :user_id
        ");
        let params = params! {
            "user_id" => user_id.ur_string()
        };

        let mut receipts = HashSet::new();
        let result: Vec<Row> = conn.exec(query, params).await?;
        for row in result {
            let receipt_string: String = row.get("receipt").unwrap();
            let receipt_envelope = Envelope::from_ur_string(receipt_string).unwrap();
            let receipt = Receipt::try_from(receipt_envelope).unwrap();
            receipts.insert(receipt);
        }

        Ok(receipts)
    }

    async fn receipt_to_record(&self, receipt: &Receipt) -> Result<Option<Record>> {
        let mut conn = self.pool.get_conn().await?;
        let schema_name = self.schema_name();
        let query = format!(r"
            SELECT user_id, data
            FROM {schema_name}.{RECORDS_TABLE_NAME}
            WHERE receipt = :receipt
        ");
        let params = params! {
            "receipt" => receipt.to_envelope().ur_string()
        };

        let result: Option<Row> = conn.exec_first(query, params).await?;
        if let Some(row) = result {
            let user_id_string: String = row.get("user_id").unwrap();
            let user_id = XID::from_ur_string(user_id_string).unwrap();
            let data: Vec<u8> = row.get("data").unwrap();
            let record = Record::new_opt(receipt.clone(), user_id, data.into());

            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn delete_record(&self, receipt: &Receipt) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = "DELETE FROM records WHERE receipt = :receipt";
        let params = params! {
            "receipt" => receipt.to_envelope().ur_string()
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn set_user_xid_document(
        &self,
        user_id: XID,
        new_xid_document: &XIDDocument,
    ) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query =
            "UPDATE users SET xid_document = :new_xid_document WHERE user_id = :user_id";
        let params = params! {
            "user_id" => user_id.ur_string(),
            "new_xid_document" => new_xid_document.ur_string(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn set_user_recovery(&self, user: &User, recovery: Option<&str>) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = "UPDATE users SET recovery = :recovery WHERE user_id = :user_id";
        let params = params! {
            "recovery" => recovery,
            "user_id" => user.user_id().ur_string(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn remove_user(&self, user: &User) -> Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = "DELETE FROM users WHERE user_id = :user_id";
        let params = params! {
            "user_id" => user.user_id().ur_string(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn recovery_to_user(&self, recovery: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get_conn().await?;
        let query = "SELECT user_id, xid_document, recovery FROM users WHERE recovery = :recovery";
        let params = params! {
            "recovery" => recovery
        };

        let result: Option<Row> = conn.exec_first(query, params).await?;
        if let Some(row) = result {
            Ok(Some(row_to_user(row)))
        } else {
            Ok(None)
        }
    }
}

fn row_to_user(row: Row) -> User {
    let user_id_string: String = row.get("user_id").unwrap();
    let _user_id = XID::from_ur_string(user_id_string).unwrap();
    let xid_document_string: String = row.get("xid_document").unwrap();
    let xid_document = XIDDocument::from_ur_string(xid_document_string).unwrap();
    let recovery: Option<String> = row.get_opt("recovery").unwrap().ok();

    User::new_opt(xid_document, recovery)
}

impl Depo {
    pub async fn new_db(schema_name: impl AsRef<str>) -> Result<Self> {
        Ok(Self::new(DbDepoImpl::new(schema_name).await?))
    }
}

pub fn server_url() -> Url {
    let mut server_url = Url::parse("mysql://").unwrap();
    server_url.set_host(Some(HOST)).unwrap();
    server_url.set_username(USER).unwrap();
    server_url.set_password(PASSWORD).unwrap();
    server_url.set_port(Some(PORT)).unwrap();
    server_url
}

pub fn database_url(schema_name: &str) -> Url {
    let mut database_url = server_url();
    database_url.set_path(schema_name);
    database_url
}

pub fn server_pool() -> Pool {
    Pool::new(server_url().as_str())
}

pub fn db_pool(schema_name: &str) -> Pool {
    Pool::new(database_url(schema_name).as_str())
}

pub async fn drop_db(server_pool: &Pool, schema_name: &str) -> Result<()> {
    let query = format!(r"
        DROP DATABASE IF EXISTS {schema_name}
    ");
    server_pool.get_conn().await?.query_drop(query).await?;

    Ok(())
}

pub async fn create_db(server_pool: &Pool, schema_name: &str) -> Result<()> {
    let query = format!(r"
        CREATE DATABASE IF NOT EXISTS {schema_name}
    ");
    server_pool.get_conn().await?.query_drop(query).await?;

    let query = format!(r"
        CREATE TABLE IF NOT EXISTS {schema_name}.{USERS_TABLE_NAME} (
            user_id VARCHAR(100) NOT NULL,
            xid_document VARCHAR(1000) UNIQUE NOT NULL,
            recovery VARCHAR(1000),
            PRIMARY KEY (user_id),
            INDEX (xid_document),
            INDEX (recovery)
        )
    ");
    server_pool.get_conn().await?.query_drop(query).await?;

    let query = format!(r"
        CREATE TABLE IF NOT EXISTS {schema_name}.{RECORDS_TABLE_NAME} (
            receipt VARCHAR(150) NOT NULL,
            user_id VARCHAR(100) NOT NULL,
            data BLOB NOT NULL,
            PRIMARY KEY (receipt),
            INDEX (user_id),
            FOREIGN KEY (user_id) REFERENCES {schema_name}.{USERS_TABLE_NAME}(user_id) ON DELETE CASCADE
        )
    ");

    server_pool.get_conn().await?.query_drop(query).await?;
    let query = format!(r"
        CREATE TABLE IF NOT EXISTS {schema_name}.{SETTINGS_TABLE_NAME} (
            private_keys VARCHAR(500),
            public_keys VARCHAR(500),
            continuation_expiry_seconds INT UNSIGNED,
            max_data_size INT UNSIGNED
        )
    ");
    server_pool.get_conn().await?.query_drop(query).await?;

    // Check if settings already exist
    let check_query = format!(r"
        SELECT COUNT(*)
        FROM {schema_name}.{SETTINGS_TABLE_NAME}
    ");
    let count: u64 = server_pool
        .get_conn().await?
        .query_first(check_query).await?
        .unwrap_or(0);

    // Only insert if settings do not exist
    if count == 0 {
        let (private_keys, public_keys) = keypair();
        let private_keys = private_keys.ur_string();
        let public_keys = public_keys.ur_string();

        let query = format!(r"
            INSERT INTO {schema_name}.{SETTINGS_TABLE_NAME}
            (private_keys, public_keys, continuation_expiry_seconds, max_data_size)
            VALUES ('{private_keys}', '{public_keys}', {CONTINUATION_EXPIRY_SECONDS}, {MAX_DATA_SIZE})
        ");
        server_pool.get_conn().await?.query_drop(query).await?;
    }

    Ok(())
}

pub async fn reset_db(schema_name: &str) -> Result<()> {
    let server_pool = server_pool();
    drop_db(&server_pool, schema_name).await?;
    create_db(&server_pool, schema_name).await?;

    Ok(())
}

pub async fn create_db_if_needed(schema_name: &str) -> Result<()> {
    let server_pool = server_pool();
    create_db(&server_pool, schema_name).await?;

    Ok(())
}

pub async fn can_connect_to_db(schema_name: &str) -> Result<bool> {
    let pool = db_pool(schema_name);
    let mut conn = pool.get_conn().await?;
    conn.ping().await?;

    Ok(true)
}
