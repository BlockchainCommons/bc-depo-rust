use depo::{start_server, setup_log};
use log::error;
use nu_ansi_term::Color::Red;

#[tokio::main]
async fn main() {
    bc_envelope::register_tags();

    setup_log();

    let schema_name = "depo";

    if let Err(e) = start_server(schema_name, 5332).await {
        error!("{}", Red.paint("Could not start server. Is the database running?").to_string());
        error!("{}", Red.paint(format!("{}", e)).to_string());
    };
}
