use serde::{Deserialize, Serialize};

// Define API Request 
#[derive(Deserialize)]
pub struct APIRequest {
    pub api_key: String
}

// Define an API request with content
#[derive(Deserialize)]
pub struct APIContentRequest {
    pub api_key: String,
    pub content: String
}

// Define a text (String) response
#[derive(Serialize)]
pub struct TextResponse {
    pub response: String
}

