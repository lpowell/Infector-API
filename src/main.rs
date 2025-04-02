use axum::{
    extract::{Json, State, Path, OriginalUri},
    http::{StatusCode, HeaderMap, Request, Uri},
    routing::{get,post},
    response::Redirect,
    Router,
};
use axum_macros::debug_handler;
use axum_client_ip::{SecureClientIp, SecureClientIpSource};

use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::net::SocketAddr;


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

    // Load database URL
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "<dbstring>>".to_string());

    // Set up connection pool
    let pool = SqlitePool::connect(&db_url)
        .await
        .expect("Failed to connect to database");

    // Wrap database pool in Arc for shared state
    let shared_state = Arc::new(pool);

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
    // Default route should redirect to 

    // set ctrl+c behavior
    // ctrlc::set_handler(move || {
    //     pool.close();
    // }).expect("Could not set up handler");

    // Start the server
    let listener = TcpListener::bind("0.0.0.0:80").await.unwrap();
    tracing::info!("Server listening on {}", listener.local_addr().unwrap());
    // Connect Info allows for the extraction of the client IP address
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
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