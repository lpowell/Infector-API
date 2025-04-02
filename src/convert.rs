use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::prelude::*; // Import Base64 for encoding/decoding data

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};


use anyhow::Result;

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
    Json(payload): Json<api_structs::APIContentRequest>,
) -> Result<Json<api_structs::TextResponse>, StatusCode> {

    // return the valid return of a resource 
    return match path.as_str() {
        "base64" => base64(State(pool),Json(payload)).await,
        "aesgcm" => encryption(State(pool),Json(payload)).await,
        _ => return     
            Err(StatusCode::NOT_FOUND)
    }
}

pub async fn base64(
    State(pool): State<Arc<SqlitePool>>,
    Json(payload): Json<api_structs::APIContentRequest>,
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
    let mut response = String::new();
    if let Err(e) = BASE64_STANDARD.decode(&payload.content) {
        response = format!("Failed to decode Base64 with error: {}", e);
        
    } else {
        response = String::from_utf8(BASE64_STANDARD.decode(&payload.content).expect("Failed to decode Base64 URL")).unwrap();
    }

    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}


pub async fn encryption(
    State(pool): State<Arc<SqlitePool>>,
    Json(payload): Json<api_structs::APIContentRequest>,
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

    // This is where the API resource code goes
    let key_str: String;
    let nonce: String;


    match payload.key {
        Some(data) => key_str = data,
        None => {
            let response = "Please submit a valid key in your payload".to_string();
            return Ok(Json(api_structs::TextResponse{
                response
            }))
        }
    }
    match payload.nonce {
        Some(data) => nonce = data,
        None => {
            let response = "Please submit a valid nonce in your payload".to_string();
            return Ok(Json(api_structs::TextResponse{
                response
            }))
        }
    }


    /*

        AES-GCM decryption
        Content must be hex and appended with the tag.
        Nonce must be 12 bytes. Support for U16 nonces may be intergrated.

        Example:

        plaintext: hello, world! I'm a big fan of cookies.
        key: 53215631996200347719740864128938
        nonce: 123456789101

        ciphertext: 38aa7d37108c31a8e0372430e3e625dd84119c2463c1bd3b612ac87a02bd1b1a368b76116553bb
        tag: 415afd2bddf82b294a977c86940c1f0e

        request:
        {
            'api_key': 'key',
            'content': '38aa7d37108c31a8e0372430e3e625dd84119c2463c1bd3b612ac87a02bd1b1a368b76116553bb415afd2bddf82b294a977c86940c1f0e',
            'key': '53215631996200347719740864128938,
            'nonce': '123456789101'
        }

        This function will only decrypt valid AES-GCM encrypted data. 
        At some point, CBC will be added. https://docs.rs/cbc/latest/cbc/. 
        Other variations are unlikely to be supported. 

        Other encryption schemes in progress are RSA, ChaCha20, and RSA. 

    */
    
    let response: String;

    let key = Key::<Aes256Gcm>::from_slice(key_str.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce.as_bytes());

    let encrypted_data: Vec<u8> = hex::decode(payload.content).unwrap();
    
    match cipher.decrypt(nonce, &*encrypted_data ) {
        Ok(plaintext) => response = String::from_utf8(plaintext).unwrap(),
        Err(e) => response = format!("Error: {} when attempting to decrypt data", e)
    }


    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}