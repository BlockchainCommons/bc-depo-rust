mod db_depo;
mod depo_impl;
mod function;
mod log;
mod mem_depo;
mod record;
mod recovery_continuation;
mod server;
mod user;

pub use db_depo::{can_connect_to_db, create_db_if_needed, reset_db};
pub use function::Depo;
pub use log::setup_log;
pub use server::start_server;

const MAX_DATA_SIZE: u32 = 1000;
const CONTINUATION_EXPIRY_SECONDS: u64 = 60 * 60 * 24;
