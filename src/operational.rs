use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
    routing::{get,post},
    response::Redirect,
    Router,
};
use axum_macros::debug_handler;
use rand::{distr::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Sqlite, SqlitePool};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::fs;

// Must import api_structs 
use crate::api_structs;

// Routing function
// this function matches a valid path to a resource
// all paths should be in the form of <url>/<endpoint>/<resource>
pub async fn route(
    State(pool): State<Arc<SqlitePool>>,
    Path(path): Path<String>,
    Json(payload): Json<api_structs::APIRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    
    // return the valid return of a resource 
    return match path.as_str() {
        "list" => list(State(pool),Json(payload)).await,
        _ => return     
            Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub async fn list(
    State(pool): State<Arc<SqlitePool>>,
    Json(payload): Json<api_structs::APIRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {
    // Get the submitted API key
    let api_key = payload.api_key;


    // SELECT API key from the database
    let expired = sqlx::query!(
        "SELECT expire_time FROM infector_auth WHERE api_key = ?1",
        api_key
    )
    .fetch_optional(& *pool)
    .await;

    // Match for DB result
    match expired {
        Ok(Some(row)) => {
            
            // Get the api key expire time and convert to an u64 
            let cmp_time: u64 = row.expire_time
                .clone()
                .unwrap()
                .parse()
                .expect("A number should be here...");
            
            // Helpful message for logging    
            tracing::info!("API key found, expire_time: {}", row.expire_time.unwrap());
            
            // Get the current time
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            // Test if the expire time is valid 
            if  current_time >= cmp_time {
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Ok(None) => {
            tracing::warn!("API key not found: {}", api_key);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            tracing::error!("Database select failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    // This is where the API resource code goes
    let response = fs::read_to_string("../README.md").expect("readme should be here...");

    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}
