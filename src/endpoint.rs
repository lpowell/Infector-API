use axum::{
    extract::{Json, State, Path},
    http::StatusCode,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use phf::{phf_map};
use curl::easy::Easy; 

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
        "script" => script(State(pool),Json(payload)).await,
        "list" => list(State(pool),Json(payload)).await,
        _ => return     
            Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/*
HashMap for github scripts
Structure is short_name; raw_url;
*/

const github_scripts: phf::Map<&'static str, &'static str> = phf_map! {
    "fileanalysis" => "https://raw.githubusercontent.com/lpowell/Invoke-FileAnalysis/refs/heads/main/Invoke-FileAnalysis.psm1",
    "vynae" => "https://raw.githubusercontent.com/lpowell/Vynae/refs/heads/main/Vynae.ps1",
    // "beardeddragon" => "https://raw.githubusercontent.com/lpowell/BeardedDragon/refs/heads/main/BeardedDragon.ps1",
    // beardeddragon is encoded funny and doesn't work lol
    "ginger" => "https://raw.githubusercontent.com/lpowell/GingerRoot/refs/heads/main/Ginger.ps1"
};

fn find_script(
    script_name: &String
) -> Result<String, String> {

    // Test if value is in hashmap
    if !github_scripts.contains_key(script_name.as_str()) {
        return Err("Could not find the requested script name. Try listing available scripts.".to_string());
    }

    let mut response = String::new();
    match github_scripts.get(script_name.as_str()) {
        Some(url) => response = format!("{}", url),
        None => response = format!("script not found")
    }

    let mut e = Easy::new();
    e.url(response.as_str()).unwrap();

    let mut data = Vec::new();

    {
        let mut t = e.transfer();
        t.write_function(|new_data| {
            data.extend_from_slice(new_data);
            Ok(new_data.len())
        }).unwrap();
        t.perform().unwrap();
    }

    Ok(String::from_utf8(data).unwrap())

}


pub async fn script(
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

    /*  This is where the API resource code goes
        Notes:
            - Try to return errors when possible. 
            - Ensure that output is clear and concise when possible.
    */
    let script = payload.content;
    let mut response = String::new();
    // if let Err(e) = find_script(&script) {
    //     response = format!("Failed with error: {}", e);
    // } else {

    // }
    match find_script(&script) {
        Ok(data) => response = data,
        Err(e) => response = format!("Could not retrieve script: {}",e)
    };

    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}


pub async fn list(
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

    /*  This is where the API resource code goes
        Notes:
            - Try to return errors when possible. 
            - Ensure that output is clear and concise when possible.
    */
    let mut response = String::new();
    for (short_name, raw_url) in &github_scripts {
        response += format!("Short_Name: {}, Raw_URL: {}\n",short_name, raw_url).as_str();
    };

    // Return value must be wrapped in a TextResponse struct
    Ok(Json(api_structs::TextResponse{
        response
    }))

}
