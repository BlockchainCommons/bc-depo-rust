use std::future::Future;

use anyhow::Result;
use log::info;
use nu_ansi_term::Color::Green;
use warp::{
    Filter,
    http::StatusCode,
    reject::Rejection,
    reply::{self, Reply},
};

use crate::{
    Depo,
    db_depo::{create_db, server_pool},
    reset_db,
};

/// Returns a future that runs the server. Call `.await` on the returned future
/// to start the server, or spawn it into a separate task.
pub async fn start_server(
    schema_name: String,
    port: u16,
) -> Result<impl Future<Output = ()> + Send> {
    create_db(&server_pool(), &schema_name).await?;

    let depo = Depo::new_db(&schema_name).await?;

    let key_route = warp::path::end()
        .and(warp::get())
        .and(with_depo(depo.clone()))
        .and_then(key_handler);

    let operation_route = warp::path::end()
        .and(warp::post())
        .and(with_depo(depo.clone()))
        .and(warp::body::bytes())
        .and_then(operation_handler);

    let cloned_schema_name = schema_name.clone();

    let reset_db_route = warp::path("reset-db".to_owned())
        .and(warp::post())
        .and(warp::any().map(move || cloned_schema_name.clone()))
        .and_then(reset_db_handler);

    let routes = key_route.or(operation_route).or(reset_db_route);

    let host = "127.0.0.1";
    let addr = format!("{}:{}", host, port);
    let socket_addr = addr.parse::<std::net::SocketAddr>()?;

    info!(
        "{}",
        Green.paint(format!(
            "Starting Blockchain Commons Depository on {}:{}",
            host, port
        ))
    );
    info!(
        "{}",
        Green.paint(format!(
            "Server XIDDocument: {}",
            depo.public_xid_document_string()
        ))
    );

    // Workaround for warp 0.4 lifetime issue with tokio::spawn
    // See: https://github.com/seanmonstar/warp/issues/1130
    let server = warp::serve(routes).bind(socket_addr).await;
    Ok(server.run())
}

fn with_depo(
    depo: Depo,
) -> impl Filter<Extract = (Depo,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || depo.clone())
}

async fn key_handler(depo: Depo) -> Result<Box<dyn Reply>, Rejection> {
    Ok(Box::new(reply::with_status(
        depo.public_xid_document_string().to_string(),
        StatusCode::OK,
    )))
}

async fn operation_handler(
    depo: Depo,
    body: bytes::Bytes,
) -> Result<Box<dyn Reply>, Rejection> {
    let body_string = std::str::from_utf8(&body)
        .map_err(|_| warp::reject::custom(InvalidBody))?
        .to_string();
    let a = depo.handle_request_string(body_string).await;
    let result: Box<dyn Reply> =
        Box::new(reply::with_status(a, StatusCode::OK));
    Ok(result)
}

async fn reset_db_handler(
    schema_name: String,
) -> Result<Box<dyn Reply>, Rejection> {
    match reset_db(&schema_name).await {
        Ok(_) => Ok(Box::new(reply::with_status(
            "Database reset successfully. A new private key has been assigned. Server must be restarted.",
            StatusCode::OK,
        ))),
        Err(e) => {
            let error_message = format!("Failed to reset database: {}", e);
            let reply = reply::html(error_message);
            Ok(Box::new(reply::with_status(
                reply,
                StatusCode::INTERNAL_SERVER_ERROR,
            )))
        }
    }
}

#[derive(Debug)]
struct InvalidBody;
impl warp::reject::Reject for InvalidBody {}

// #[derive(Debug)]
// struct AnyhowError(Error);
// impl warp::reject::Reject for AnyhowError {}
