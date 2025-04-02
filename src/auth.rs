use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
};
use axum_macros::debug_handler;
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// logging import
use crate::logger;


// Define user authentication request payload
#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

// Define authentication response
#[derive(Serialize)]
pub struct AuthResponse {
    api_key: String,
    expire_time: u64,
}

// Routing function for returning the correct endpoint 
pub async fn route(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    return match path.as_str() {
        "login" => auth_login(State(pool),Json(payload)).await,
        _ => return     
            Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

// Login handler
#[debug_handler]
pub async fn auth_login(
    State(pool): State<Arc<SqlitePool>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {

    // get user name from db if submitted username and password exist
    // fetch_one will error if no rows are returned
    if let Err(e) = sqlx::query!(
        "SELECT * FROM infector_users WHERE user_name = ?1 AND user_pass = ?2",
        payload.username, payload.password
    )
    .fetch_one(& *pool)
    .await{
        tracing::error!("Database lookup failed: {}", e);
        let warning = format!("[WARNING] Database lookup up failed! [user] {} [error] {}", payload.username, e);
        logger::writelog("access",warning);
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Validate user credentials
    // if payload.username != valid_user || payload.password != valid_pass {
    //     return Err(StatusCode::UNAUTHORIZED);
    // }

    // Generate random API key
    let api_key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Set expiration time (30 minutes from now)
    let expire_time = SystemTime::now()
        .checked_add(Duration::from_secs(1800))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expire = expire_time.to_string();
    // explicit commit 
    let mut tx = pool.begin().await.expect("Failed to start transaction");

    // Insert API key into the database
    if let Err(e) = sqlx::query!(
        "INSERT INTO infector_auth (api_key, expire_time) VALUES (?1, ?2) RETURNING api_key",
        api_key,
        expire
    )
    .fetch_all(&mut *tx)
    .await
    {
        tracing::error!("Database insert failed: {}", e);
        let info = format!("[INFO] Database API Key insertion failed! [error] {}", e);
        logger::writelog("transaction", info);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // explicit commit
    tx.commit().await.expect("Failed to commit transaction");
    tracing::info!("Transaction committed successfully!");

    // Return response
    Ok(Json(AuthResponse {
        api_key,
        expire_time,
    }))
}
