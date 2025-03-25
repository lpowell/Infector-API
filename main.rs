use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
    routing::{get,post},
    response::Redirect,
    Router,
};
use axum_macros::debug_handler;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

// Begin handlers

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("debug"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load database URL
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://".to_string());

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
        .route("/convert/{path}", get(convert))
        .route("/operational/{path}", get(operational))
        .route("/", get(|| async { Redirect::permanent("")}))
        .with_state(shared_state);
    // Default route should redirect to 


    // Start the server
    let listener = TcpListener::bind("0.0.0.0:80").await.unwrap();
    tracing::info!("Server listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}


// Handlers for each api endpoint
// Routing is handled within the source for each 
// All endpoint functions should return appropriately 
#[debug_handler]
async fn testing(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<api_structs::APIRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    println!("Resource requested: {path}");
    let response = testing::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn auth(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<auth::LoginRequest>,
) -> Result<Json<auth::AuthResponse>, StatusCode> {
    println!("Resource requested: {path}");
    let response = auth::route(State(pool),Path(path),Json(payload)).await;
    return response;
}


#[debug_handler]
async fn scanner(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<api_structs::APIContentRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    println!("Resource requested: {path}");
    let response = scanner::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn convert(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<api_structs::APIContentRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    println!("Resource requested: {path}");
    let response = convert::route(State(pool),Path(path),Json(payload)).await;
    return response;
}

#[debug_handler]
async fn operational(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<api_structs::APIRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    println!("Resource requested: {path}");
    let response = operational::route(State(pool),Path(path),Json(payload)).await;
    return response;
}