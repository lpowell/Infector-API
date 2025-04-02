use serde::{Deserialize, Serialize};
use std::fmt;

// Define API Request 
#[derive(Deserialize)]
pub struct APIRequest {
    pub api_key: String
}

// Define an API request with content
#[derive(Deserialize)]
pub struct APIContentRequest {
    pub api_key: String,
    pub content: String,

    #[serde(default)]
    pub key: Option<String>,
    pub nonce: Option<String>,
}

// Define a text (String) response
#[derive(Serialize)]
pub struct TextResponse {
    pub response: String
}

impl fmt::Display for APIRequest {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "{{[required] key: {} }}", self.api_key)
    }
}

impl fmt::Display for APIContentRequest {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Write strictly the first element into the supplied output
        // stream: `f`. Returns `fmt::Result` which indicates whether the
        // operation succeeded or failed. Note that `write!` uses syntax which
        // is very similar to `println!`.
        write!(f, "{{[required] api_key: {}, content: {}, [optional] key: {:?}, nonce: {:?} }}", self.api_key, self.content, self.key, self.nonce)
    }
}
