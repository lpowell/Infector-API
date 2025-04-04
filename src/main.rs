#![allow(unused_imports)]


use axum::{
    extract::{Json, State, Path, OriginalUri},
    http::{uri::Authority, StatusCode, HeaderMap, Request, Uri},
    routing::{get,post},
    response::Redirect,
    Extension,
    middleware::AddExtension,
    Router,
    BoxError,
    handler::HandlerWithoutStateExt,
};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use axum_macros::debug_handler;
use axum_extra::extract::Host;
use axum_client_ip::{SecureClientIp, SecureClientIpSource};
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use clap::Parser;
use std::path::PathBuf;
use tokio_stream::StreamExt;
use from_os_str::*;


use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::{Ipv6Addr, SocketAddr};


// logging
mod logger;

// auth resource for logging
mod auth;

// testing resource for testing features
mod testing;

// resource for holding prevalent structs
mod api_structs;

// resource for performing/utilizing scans
mod scanner;

// resource for performing data conversions
mod convert;

// resource for operational requests
mod operational;

// resource for handling endpoint interaction
mod endpoint;


// Ports struct for redirect
#[allow(dead_code)]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

// Begin handlers

#[tokio::main]
async fn main() {
    // Initialize tracing
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::EnvFilter::new("debug"))
    //     .with(tracing_subscriber::fmt::layer())
    //     .init();

    // tracing logs to /var/log/infector_api/transaction.log
    logger::init_logger();

    //SSL https://github.com/FlorianUekermann/rustls-acme/blob/main/examples/low_level_axum.rs
    let mut tls_inc = AcmeConfig::new(["<domain>"]) // domain 
        .contact_push("mailto: <your address>") // email (must be valid)
        .cache(DirCache::new("./rustls_acme_cache")) // cert cache
        .directory_lets_encrypt(true) // true = prod | false = test
        .state();
    let acceptor = tls_inc.axum_acceptor(tls_inc.default_rustls_config()); // create axum acceptor

    // Logging for rustls-acme cert get/validation
    // Keeping this printing for now. Will likely go into resource log.
    tokio::spawn(async move {
        loop {
            match tls_inc.next().await.unwrap() {
                Ok(ok) => println!("event: {:?}", ok),
                Err(err) => println!("error: {:?}", err),
            }
        }
    });

    // Load database URL
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "<dbpath>".to_string());

    // Set up connection pool
    let pool = SqlitePool::connect(&db_url)
        .await
        .expect("Failed to connect to database");

    // Wrap database pool in Arc for shared state
    let shared_state = Arc::new(pool);

    // redirtect http to https
    let ports = Ports {
        http: 80,
        https: 443
    };

    // Spawn HTTP server thread for redirecting requests to HTTPS
    tokio::spawn(redirect_http_to_https(ports));


    // Define the router
    let app = Router::new()
        .route("/auth/{path}", post(auth))
        .route("/testing/{path}", get(testing))
        .route("/scanner/{path}", get(scanner))
        .route("/convert/encryption/{path}", get(convert))
        .route("/convert/{path}", get(convert))
        .route("/operational/{path}", get(operational))
        .route("/endpoint/{path}", get(endpoint))
        .route("/", get(|| async { Redirect::permanent("https://alertoverload.com")}))
        // Debug route to collect headers
        .route( "/hdrs", axum::routing::get(|hdrs: axum::http::HeaderMap| async move { format!("{:#?}", hdrs) }))
        // Layer connect info to extension to support client ip extraction
        .layer(SecureClientIpSource::ConnectInfo.into_extension())
        .with_state(shared_state);


    // Start the server
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 443));

    // no spin up logs 
    // tracing::info!("Server listening on {}", listener.local_addr().unwrap());

    // bind on address and acceptor
    let server = axum_server::bind(addr).acceptor(acceptor);

    // redirect http here maybe

    // Connect Info allows for the extraction of the client IP address
    server.serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

// HTTP redirect https://github.com/tokio-rs/axum/blob/main/examples/tls-rustls/src/main.rs
#[allow(dead_code)]
async fn redirect_http_to_https(ports: Ports) {
    fn make_https(host: &str, uri: Uri, https_port: u16) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();

        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
        }

        let authority: Authority = host.parse()?;
        let bare_host = match authority.port() {
            Some(port_struct) => authority
                .as_str()
                .strip_suffix(port_struct.as_str())
                .unwrap()
                .strip_suffix(':')
                .unwrap(), // if authority.port() is Some(port) then we can be sure authority ends with :{port}
            None => authority.as_str(),
        };

        parts.authority = Some(format!("{bare_host}:{https_port}").parse()?);

        Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(&host, uri, ports.https) {
            Ok(uri) => Ok(Redirect::permanent(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, ports.http)); // remember to make sure you're not listening on localhost lol
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    // let log = format!("listening on {}", listener.local_addr().unwrap());
    // logger::writelog("access", log);
    axum::serve(listener, redirect.into_make_service())
        .await
        .unwrap();
}


// Handlers for each api endpoint
// Routing is handled within the source for each 
// All endpoint functions should return appropriately 
#[debug_handler]
async fn testing(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    secure_ip: SecureClientIp,
    headers: HeaderMap,
    uri: Uri, 
    OriginalUri(original_uri): OriginalUri,
    Json(payload): Json<api_structs::APIRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    // This is beatiful code and you know it
    let access = format!("[client: {}] [agent: {}] [headers] {:?} [URI] {} [payload] {}", secure_ip.0, headers.get("user-agent").unwrap().to_str().unwrap(), headers, original_uri, &payload);
    logger::writelog("access", access);
    let response = testing::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn auth(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    secure_ip: SecureClientIp,
    headers: HeaderMap,
    uri: Uri, 
    OriginalUri(original_uri): OriginalUri,
    Json(payload): Json<auth::LoginRequest>,
) -> Result<Json<auth::AuthResponse>, StatusCode> {
    let access = format!("[client: {}] [agent: {}] [headers] {:?} [URI] {}", secure_ip.0, headers.get("user-agent").unwrap().to_str().unwrap(), headers, original_uri);
    logger::writelog("access", access);
    
    let response = auth::route(State(pool),Path(path),Json(payload)).await;
    return response;
}


#[debug_handler]
async fn scanner(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    secure_ip: SecureClientIp,
    headers: HeaderMap,
    uri: Uri, 
    OriginalUri(original_uri): OriginalUri,
    Json(payload): Json<api_structs::APIContentRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    let access = format!("[client: {}] [agent: {}] [headers] {:?} [URI] {} [payload] {}", secure_ip.0, headers.get("user-agent").unwrap().to_str().unwrap(), headers, original_uri, &payload);
    logger::writelog("access", access);
    
    let response = scanner::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn convert(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    secure_ip: SecureClientIp,
    headers: HeaderMap,
    uri: Uri, 
    OriginalUri(original_uri): OriginalUri,
    Json(payload): Json<api_structs::APIContentRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    let access = format!("[client: {}] [agent: {}] [headers] {:?} [URI] {} [payload] {}", secure_ip.0, headers.get("user-agent").unwrap().to_str().unwrap(), headers, original_uri, &payload);
    logger::writelog("access", access);
    
    let response = convert::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn endpoint(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    secure_ip: SecureClientIp,
    headers: HeaderMap,
    uri: Uri, 
    OriginalUri(original_uri): OriginalUri,
    Json(payload): Json<api_structs::APIContentRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    let access = format!("[client: {}] [agent: {}] [headers] {:?} [URI] {} [payload] {}", secure_ip.0, headers.get("user-agent").unwrap().to_str().unwrap(), headers, original_uri, &payload);
    logger::writelog("access", access);
    
    let response = endpoint::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn operational(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    secure_ip: SecureClientIp,
    headers: HeaderMap,
    uri: Uri, 
    OriginalUri(original_uri): OriginalUri,
    Json(payload): Json<api_structs::APIRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    let access = format!("[client: {}] [agent: {}] [headers] {:?} [URI] {} [payload] {}", secure_ip.0, headers.get("user-agent").unwrap().to_str().unwrap(), headers, original_uri, &payload);
    logger::writelog("access", access);
    
    let response = operational::route(State(pool),Path(path),Json(payload)).await;
    return response;
}