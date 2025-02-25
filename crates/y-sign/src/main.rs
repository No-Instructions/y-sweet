use anyhow::Result;
use clap::{Parser, Subcommand};
use y_sweet_core::auth::Authenticator;

use tokio::io::AsyncReadExt;
use std::time::SystemTime;
use y_sweet_core::{
    api_types::Authorization,
    auth::ExpirationTimeEpochMillis,
};

async fn sign_stdin(auth: &Authenticator) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut buffer = String::new();
    stdin.read_to_string(&mut buffer).await?;

    let input: serde_json::Value = serde_json::from_str(&buffer)?;
    
    // Extract fields from the JSON input
    let doc_id = input.get("docId").and_then(|v| v.as_str());
    let file_hash = input.get("fileHash").and_then(|v| v.as_str());
    let token_type = input.get("type").and_then(|v| v.as_str()).unwrap_or("document");
    let auth_str = input.get("authorization").and_then(|v| v.as_str()).unwrap_or("full");
    
    if token_type != "document" && token_type != "file" {
        anyhow::bail!("Invalid token type: {}. Must be 'document' or 'file'", token_type);
    }
    
    let authorization = match auth_str {
        "read" => Authorization::ReadOnly,
        "full" => Authorization::Full,
        other => anyhow::bail!("Invalid authorization: {}. Must be 'read' or 'full'", other),
    };

    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis() as u64;
    
    let expiration = ExpirationTimeEpochMillis(
        current_time + (y_sweet_core::auth::DEFAULT_EXPIRATION_SECONDS * 1000),
    );

    let mut output = serde_json::Map::new();
    
    match token_type {
        "document" => {
            let doc_id = doc_id
                .ok_or_else(|| anyhow::anyhow!("docId is required for document tokens"))?;
                
            let token = auth.gen_doc_token(doc_id, authorization, expiration);
            
            output.insert("docId".to_string(), serde_json::Value::String(doc_id.to_string()));
            output.insert("token".to_string(), serde_json::Value::String(token));
            output.insert("type".to_string(), serde_json::Value::String("document".to_string()));
            
            let auth_value = match authorization {
                Authorization::ReadOnly => "read-only",
                Authorization::Full => "full",
            };
            output.insert("authorization".to_string(), serde_json::Value::String(auth_value.to_string()));
        },
        "file" => {
            let file_hash = file_hash
                .ok_or_else(|| anyhow::anyhow!("fileHash is required for file tokens"))?;
            
            let token = auth.gen_file_token(file_hash, authorization, expiration);
            
            output.insert("fileHash".to_string(), serde_json::Value::String(file_hash.to_string()));
            output.insert("token".to_string(), serde_json::Value::String(token));
            output.insert("type".to_string(), serde_json::Value::String("file".to_string()));
            
            let auth_value = match authorization {
                Authorization::ReadOnly => "read-only",
                Authorization::Full => "full",
            };
            output.insert("authorization".to_string(), serde_json::Value::String(auth_value.to_string()));
        },
        _ => unreachable!(), // Already validated above
    }
    
    println!("{}", serde_json::Value::Object(output).to_string());
    Ok(())
}

async fn verify_stdin(auth: &Authenticator, id: Option<&str>) -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut token = String::new();
    stdin.read_to_string(&mut token).await?;
    let token = token.trim();

    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_millis() as u64;

    let mut output = serde_json::Map::new();
    let mut verification = serde_json::Map::new();
    
    // Create token info
    let mut token_info = serde_json::Map::new();
    token_info.insert("raw".to_string(), serde_json::Value::String(token.to_string()));
    
    match auth.verify_server_token(token, current_time) {
        Ok(()) => {
            verification.insert("valid".to_string(), serde_json::Value::Bool(true));
            verification.insert("kind".to_string(), serde_json::Value::String("server".to_string()));
        },
        Err(_) => {
            // This might be a document or file token
            if let Some(id) = id {
                match auth.verify_doc_token(token, id, current_time) {
                    Ok(authorization) => {
                        let auth_str = match authorization {
                            Authorization::ReadOnly => "read",
                            Authorization::Full => "full",
                        };
                        
                        verification.insert("valid".to_string(), serde_json::Value::Bool(true));
                        verification.insert("authorization".to_string(), serde_json::Value::String(auth_str.to_string()));
                        
                        // Assume document type for simplicity
                        verification.insert("kind".to_string(), serde_json::Value::String("document".to_string()));
                        verification.insert("docId".to_string(), serde_json::Value::String(id.to_string()));
                    }
                    Err(e) => {
                        verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                        verification.insert("kind".to_string(), serde_json::Value::String("document".to_string()));
                        verification.insert("docId".to_string(), serde_json::Value::String(id.to_string()));
                        verification.insert("error".to_string(), serde_json::Value::String(e.to_string()));
                    },
                }
            } else {
                verification.insert("valid".to_string(), serde_json::Value::Bool(false));
                verification.insert("kind".to_string(), serde_json::Value::String("unknown".to_string()));
                verification.insert("error".to_string(), serde_json::Value::String("No ID provided for verification".to_string()));
            }
        },
    };

    output.insert("token".to_string(), serde_json::Value::Object(token_info));
    output.insert("verification".to_string(), serde_json::Value::Object(verification));
    
    println!("{}", serde_json::Value::Object(output).to_string());
    Ok(())
}

/// Y-Sign is a tool for signing and verifying tokens for y-sweet
#[derive(Parser)]
#[clap(version)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SignSubcommand,
}

#[derive(Subcommand)]
enum SignSubcommand {
    /// Generate a token for a document or file
    Sign {
        /// The authentication key for signing tokens
        #[clap(long, env = "Y_SWEET_AUTH")]
        auth: String,
    },

    /// Verify a token for a document or file
    Verify {
        /// The authentication key for verifying tokens
        #[clap(long, env = "Y_SWEET_AUTH")]
        auth: String,

        /// The document ID to verify against
        #[clap(long)]
        doc_id: Option<String>,
        
        /// The file hash to verify against
        #[clap(long)]
        file_hash: Option<String>,
    },

    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    // No need for complex logging setup in this simple tool

    match &opts.subcmd {
        SignSubcommand::Sign { auth } => {
            let authenticator = Authenticator::new(auth)?;
            sign_stdin(&authenticator).await?;
        }
        SignSubcommand::Verify { auth, doc_id, file_hash } => {
            let authenticator = Authenticator::new(auth)?;
            // Use the doc_id if provided, otherwise use file_hash if provided
            let id = doc_id.as_deref().or(file_hash.as_deref());
            verify_stdin(&authenticator, id).await?;
        }
        SignSubcommand::Version => {
            println!("{}", env!("CARGO_PKG_VERSION"));
        }
    }

    Ok(())
}