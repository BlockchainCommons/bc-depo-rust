use depo::start_server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    start_server().await
}
