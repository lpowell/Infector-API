use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::process::Command;
use curl::easy::{Easy, List}; 
use is_ip::*;
use addr::parse_domain_name;

// Must import api_structs 
use crate::api_structs;

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
        "nmap" => nmap(State(pool),Json(payload)).await,
        "shodan" => shodan(State(pool),Json(payload)).await,
        "virustotal" => virustotal(State(pool),Json(payload)).await,
        _ => return     
            Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub async fn nmap(
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

    // write something to parse out command line options and add them as args
    // maybe into a list with .into_iterator or something 

    let output = Command::new("nmap")
        .arg(payload.content)
        .output()
        .unwrap();

    let response = String::from_utf8(output.stdout).unwrap();


    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}

pub async fn shodan(
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

    let shodan_key = "";
    let shodan_url = format!("https://api.shodan.io/shodan/host/{}?key={}",payload.content,shodan_key);


    let mut e = Easy::new();
    e.url(&shodan_url.as_str()).unwrap();

    let mut data = Vec::new();

    {
        let mut t = e.transfer();
        t.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        }).unwrap();
        t.perform().unwrap();
    }

    let response = String::from_utf8(data).expect("Shodan results should be here...");


    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}


pub async fn virustotal(
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

    let virustotal_key = "";
    let virustotal_url = format!("https://www.virustotal.com");

    // match content type to endpoints
    let content = payload.content;

    let mut stub: String = String::new();

    if is_ip(content.as_str()) {
        // content is ip
        println!("found: ip");
        stub = format!("{}/api/v3/ip_addresses/{}",virustotal_url, content);
    }else if parse_domain_name(content.as_str()).unwrap().has_known_suffix() {
        // content is domain
        println!("found: domain");
        stub = format!("{}/api/v3/domains/{}",virustotal_url, content);
    } else {
        // assume content is hash
        println!("found: hash");
        stub = format!("{}/api/v3/files/{}",virustotal_url, content);
    }


    let mut e = Easy::new();
    e.url(&stub.as_str()).unwrap();
    
    let mut headers: List = List::new();
    headers.append("accept: application/json");
    headers.append(format!("x-apikey: {}",virustotal_key).as_str());

    e.http_headers(headers);


    let mut data = Vec::new();

    {
        let mut t = e.transfer();
        t.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        }).unwrap();
        t.perform().unwrap();
    }

    let response = String::from_utf8(data).expect("Shodan results should be here...");


    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}