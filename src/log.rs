use std::sync::Once;

use env_logger::Builder;
use log::LevelFilter;

static INIT: Once = Once::new();

pub fn setup_log() {
    INIT.call_once(|| {
        Builder::new().filter(None, LevelFilter::Info).init();
        // Builder::from_env(
        //     Env::default()
        //         .default_filter_or("depo=info")
        //     )
        //     .init();
        // println!("LOGGING INITIALIZED")
    });
}
