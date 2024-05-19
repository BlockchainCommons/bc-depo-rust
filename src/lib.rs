mod db_depo;
mod depo_impl;
mod function;
mod mem_depo;
mod record;
mod recovery_continuation;
mod user;
mod server;
mod log;

pub use function::Depo;
pub use server::start_server;
pub use log::setup_log;
pub use db_depo::{reset_db, can_connect_to_db, create_db_if_needed};

const MAX_DATA_SIZE: u32 = 1000;
const CONTINUATION_EXPIRY_SECONDS: u64 = 60 * 60 * 24;
