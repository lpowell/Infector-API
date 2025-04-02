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

// Must import api_structs 
use crate::api_structs;

// logging import
use crate::logger;

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
        "resource" => hello_world(State(pool),Json(payload)).await,
        _ => return     
            Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub async fn resource(
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
                let warning = format!("[INFO] API Key expired! [key] {}", api_key);
                logger::writelog("access", warning);
                return Err(StatusCode::UNAUTHORIZED);
            }
            let info = format!("[INFO] API Key validated [key] {}", api_key);
            logger::writelog("access", info);

        }
        Ok(None) => {
            tracing::warn!("API key not found: {}", api_key);
            // Issue a warning if the key is not in the database
            let warning = format!("[WARNING] API Key not found! [key] {}", api_key);
            logger::writelog("access", warning);
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            tracing::error!("Database select failed: {}", e);
            let error = format!("[ERROR] Database select failed!");
            logger::writelog("transaction", error);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }

    /*  This is where the API resource code goes
        Notes:
            - Try to return errors when possible. 
            - Ensure that output is clear and concise when possible.
    */
    let mut response = String::new();
    if let Err(e) = my_function() {
        response = format!("Failed with error: {}", e);
    } else {
        response = "";
    }

    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}
