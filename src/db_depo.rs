use std::{collections::HashSet, env, sync::Arc};

use crate::depo_impl::DepoImpl;
use crate::function::Depo;
use crate::record::Record;
use crate::user::User;
use anyhow::anyhow;
use async_trait::async_trait;
use bc_components::{PrivateKeyBase, PublicKeyBase, ARID};
use bc_envelope::prelude::*;
use depo_api::receipt::Receipt;
use mysql_async::{prelude::*, Pool, Row};
use url::Url;

use bc_server_api::{CONTINUATION_EXPIRY_SECONDS, MAX_DATA_SIZE};

const USER: &str = "root";
const PASSWORD: Option<&str> = None;
// @todo Make hostname configurable because if depo is running in Docker then it needs the db container's hostname.
const HOST: &str = "localhost";
const PORT: u16 = 3306;

const USERS_TABLE_NAME: &str = "users";
const RECORDS_TABLE_NAME: &str = "records";
const SETTINGS_TABLE_NAME: &str = "settings";

struct DbDepoImpl {
    schema_name: String,
    pool: Pool,
    private_key: PrivateKeyBase,
    public_key: PublicKeyBase,
    public_key_string: String,
    continuation_expiry_seconds: u32,
    max_data_size: u32,
}

impl DbDepoImpl {
    async fn new(schema_name: impl AsRef<str>) -> anyhow::Result<Arc<Self>> {
        let schema_name = schema_name.as_ref().to_string();
        let pool = db_pool(&schema_name);
        let (private_key, continuation_expiry_seconds, max_data_size) =
            get_settings(&pool, &schema_name).await?;
        let public_key = private_key.public_keys();
        let public_key_string = public_key.ur_string();
        Ok(Arc::new(Self {
            schema_name,
            pool,
            private_key,
            public_key,
            public_key_string,
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
) -> anyhow::Result<(PrivateKeyBase, u32, u32)> {
    let mut conn = pool.get_conn().await?;
    let query = format!(
        "SELECT private_key, continuation_expiry_seconds, max_data_size FROM {}.{}",
        schema_name, SETTINGS_TABLE_NAME
    );

    let result: Option<Row> = conn.query_first(query).await?;
    match result {
        Some(row) => {
            let private_key_string: String = row
                .get("private_key")
                .ok_or_else(|| anyhow!("Private key not found"))?;
            let private_key = PrivateKeyBase::from_ur_string(private_key_string)?;
            let continuation_expiry_seconds: u32 = row
                .get("continuation_expiry_seconds")
                .ok_or_else(|| anyhow!("Continuation expiry seconds not found"))?;
            let max_data_size: u32 = row
                .get("max_data_size")
                .ok_or_else(|| anyhow!("Max payload size not found"))?;

            Ok((private_key, continuation_expiry_seconds, max_data_size))
        }
        None => Err(anyhow!("Settings not found")),
    }
}

#[async_trait]
impl DepoImpl for DbDepoImpl {
    fn max_data_size(&self) -> u32 {
        self.max_data_size
    }

    fn continuation_expiry_seconds(&self) -> u32 {
        self.continuation_expiry_seconds
    }

    fn private_key(&self) -> &PrivateKeyBase {
        &self.private_key
    }

    fn public_key(&self) -> &PublicKeyBase {
        &self.public_key
    }

    fn public_key_string(&self) -> &str {
        &self.public_key_string
    }

    async fn existing_key_to_id(&self, public_key: &PublicKeyBase) -> anyhow::Result<Option<ARID>> {
        let user = key_to_user(&self.pool, public_key).await?;
        let id = user.map(|user| user.user_id().clone());
        Ok(id)
    }

    async fn existing_id_to_user(&self, user_id: &ARID) -> anyhow::Result<Option<User>> {
        let mut conn = self.pool.get_conn().await?;
        let query = "SELECT user_id, public_key, recovery FROM users WHERE user_id = :user_id";
        let params = params! {
            "user_id" => user_id.as_ref().ur_string()
        };

        let result: Option<Row> = conn.exec_first(query, params).await?;
        if let Some(row) = result {
            Ok(Some(row_to_user(row)))
        } else {
            Ok(None)
        }
    }

    async fn insert_user(&self, user: &User) -> anyhow::Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = format!("INSERT INTO {}.{} (user_id, public_key, recovery) VALUES (:user_id, :public_key, :recovery)", self.schema_name(), USERS_TABLE_NAME);
        let params = params! {
            "user_id" => user.user_id().ur_string(),
            "public_key" => user.public_key().ur_string(),
            "recovery" => user.recovery(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn insert_record(&self, record: &Record) -> anyhow::Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = format!(
            r#"
            INSERT IGNORE INTO {}.{} (receipt, user_id, data)
            VALUES (:receipt, :user_id, :data)
        "#,
            self.schema_name(),
            RECORDS_TABLE_NAME
        );
        let params = params! {
            "receipt" => record.receipt().envelope().ur_string(),
            "user_id" => record.user_id().ur_string(),
            "data" => record.data().as_ref(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn id_to_receipts(&self, user_id: &ARID) -> anyhow::Result<HashSet<Receipt>> {
        let mut conn = self.pool.get_conn().await?;
        let query = "SELECT receipt FROM records WHERE user_id = :user_id";
        let params = params! {
            "user_id" => user_id.as_ref().ur_string()
        };

        let mut receipts = HashSet::new();
        let result: Vec<Row> = conn.exec(query, params).await?;
        for row in result {
            let receipt_string: String = row.get("receipt").unwrap();
            let receipt_envelope = Envelope::from_ur_string(receipt_string).unwrap();
            let receipt = Receipt::from_envelope(receipt_envelope).unwrap();
            receipts.insert(receipt);
        }

        Ok(receipts)
    }

    async fn receipt_to_record(&self, receipt: &Receipt) -> anyhow::Result<Option<Record>> {
        let mut conn = self.pool.get_conn().await?;
        let query = "SELECT user_id, data FROM records WHERE receipt = :receipt";
        let params = params! {
            "receipt" => receipt.envelope().ur_string()
        };

        let result: Option<Row> = conn.exec_first(query, params).await?;
        if let Some(row) = result {
            let user_id_string: String = row.get("user_id").unwrap();
            let user_id = ARID::from_ur_string(user_id_string).unwrap();
            let data: Vec<u8> = row.get("data").unwrap();
            let record = Record::new_opt(receipt.clone(), user_id, data.into());

            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn delete_record(&self, receipt: &Receipt) -> anyhow::Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = "DELETE FROM records WHERE receipt = :receipt";
        let params = params! {
            "receipt" => receipt.envelope().ur_string()
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn set_user_key(
        &self,
        old_public_key: &PublicKeyBase,
        new_public_key: &PublicKeyBase,
    ) -> anyhow::Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query =
            "UPDATE users SET public_key = :new_public_key WHERE public_key = :old_public_key";
        let params = params! {
            "new_public_key" => new_public_key.ur_string(),
            "old_public_key" => old_public_key.ur_string(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn set_user_recovery(&self, user: &User, recovery: Option<&str>) -> anyhow::Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = "UPDATE users SET recovery = :recovery WHERE user_id = :user_id";
        let params = params! {
            "recovery" => recovery,
            "user_id" => user.user_id().as_ref().ur_string(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn remove_user(&self, user: &User) -> anyhow::Result<()> {
        let mut conn = self.pool.get_conn().await?;
        let query = "DELETE FROM users WHERE user_id = :user_id";
        let params = params! {
            "user_id" => user.user_id().as_ref().ur_string(),
        };

        conn.exec_drop(query, params).await?;

        Ok(())
    }

    async fn recovery_to_user(&self, recovery: &str) -> anyhow::Result<Option<User>> {
        let mut conn = self.pool.get_conn().await?;
        let query = "SELECT user_id, public_key, recovery FROM users WHERE recovery = :recovery"; // @audit Are these parameters safe to use?
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
    let user_id = ARID::from_ur_string(user_id_string).unwrap();
    let public_key_string: String = row.get("public_key").unwrap();
    let public_key = PublicKeyBase::from_ur_string(public_key_string).unwrap();
    let recovery: Option<String> = row.get_opt("recovery").unwrap().ok();

    User::new_opt(user_id, public_key, recovery)
}

impl Depo {
    pub async fn new_db(schema_name: impl AsRef<str>) -> anyhow::Result<Self> {
        Ok(Self::new(DbDepoImpl::new(schema_name).await?))
    }
}

pub async fn key_to_user(
    pool: &Pool,
    key: impl AsRef<PublicKeyBase>,
) -> anyhow::Result<Option<User>> {
    let mut conn = pool.get_conn().await?;
    let query = "SELECT user_id, public_key, recovery FROM users WHERE public_key = :key";
    let params = params! {
        "key" => key.as_ref().ur_string()
    };

    let result: Option<Row> = conn.exec_first(query, params).await?;
    if let Some(row) = result {
        Ok(Some(row_to_user(row)))
    } else {
        Ok(None)
    }
}

pub fn server_url() -> Url {
    let mut server_url = Url::parse("mysql://").unwrap();
    let host = match env::var("DB_HOST") {
        Ok(val) => String::from(val.trim_matches('"')),
        Err(_) => HOST.to_string(),
    };
    println!("Using host: {}", host);
    server_url.set_host(Some(&host)).unwrap();
    server_url.set_username(USER).unwrap();
    server_url.set_password(PASSWORD).unwrap();
    server_url.set_port(Some(PORT)).unwrap();
    println!("Server URL: {}", server_url);
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

pub async fn drop_db(server_pool: &Pool, schema_name: &str) -> anyhow::Result<()> {
    let query = format!("DROP DATABASE IF EXISTS {}", schema_name);
    server_pool.get_conn().await?.query_drop(query).await?;

    Ok(())
}

pub async fn create_db(server_pool: &Pool, schema_name: &str) -> anyhow::Result<()> {
    let query = format!("CREATE DATABASE IF NOT EXISTS {}", schema_name);
    server_pool.get_conn().await?.query_drop(query).await?;

    let query = format!(
        r"CREATE TABLE IF NOT EXISTS {}.{} (
            user_id VARCHAR(100) NOT NULL,
            public_key VARCHAR(200) UNIQUE NOT NULL,
            recovery VARCHAR(1000),
            PRIMARY KEY (user_id),
            INDEX (public_key),
            INDEX (recovery)
        )",
        schema_name, USERS_TABLE_NAME
    );
    server_pool.get_conn().await?.query_drop(query).await?;

    let query = format!(
        r"CREATE TABLE IF NOT EXISTS {}.{} (
            receipt VARCHAR(150) NOT NULL,
            user_id VARCHAR(100) NOT NULL,
            data BLOB NOT NULL,
            PRIMARY KEY (receipt),
            INDEX (user_id),
            FOREIGN KEY (user_id) REFERENCES {}.{}(user_id) ON DELETE CASCADE
        )",
        schema_name, RECORDS_TABLE_NAME, schema_name, USERS_TABLE_NAME
    );

    server_pool.get_conn().await?.query_drop(query).await?;
    let query = format!(
        r"CREATE TABLE IF NOT EXISTS {}.{} (
            private_key VARCHAR(120),
            continuation_expiry_seconds INT UNSIGNED,
            max_data_size INT UNSIGNED
        )",
        schema_name, SETTINGS_TABLE_NAME
    );
    server_pool.get_conn().await?.query_drop(query).await?;

    // Check if settings already exist
    let check_query = format!(
        "SELECT COUNT(*) FROM {}.{}",
        schema_name, SETTINGS_TABLE_NAME
    );
    let count: u64 = server_pool
        .get_conn()
        .await?
        .query_first(check_query)
        .await?
        .unwrap_or(0);

    // Only insert if settings do not exist
    if count == 0 {
        let private_key = PrivateKeyBase::new().ur_string();

        let query = format!(
            r"INSERT INTO {}.{}
            (private_key, continuation_expiry_seconds, max_data_size) VALUES ('{}', {}, {})",
            schema_name,
            SETTINGS_TABLE_NAME,
            private_key,
            CONTINUATION_EXPIRY_SECONDS,
            MAX_DATA_SIZE
        );
        server_pool.get_conn().await?.query_drop(query).await?;
    }

    Ok(())
}

pub async fn reset_db(schema_name: &str) -> anyhow::Result<()> {
    let server_pool = server_pool();
    drop_db(&server_pool, schema_name).await?;
    create_db(&server_pool, schema_name).await?;

    Ok(())
}

pub async fn create_db_if_needed(schema_name: &str) -> anyhow::Result<()> {
    let server_pool = server_pool();
    create_db(&server_pool, schema_name).await?;

    Ok(())
}

pub async fn can_connect_to_db(schema_name: &str) -> anyhow::Result<bool> {
    let pool = db_pool(schema_name);
    let mut conn = pool.get_conn().await?;
    conn.ping().await?;

    Ok(true)
}
