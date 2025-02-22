use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use url::Url;
use y_sweet_core::api_types::Authorization;
use y_sweet_core::auth::{AuthError, Authenticator};

pub fn print_server_url(auth: Option<&Authenticator>, url_prefix: Option<&Url>, addr: SocketAddr) {
    let mut url = if let Some(url_prefix) = url_prefix {
        url_prefix.clone()
    } else {
        Url::parse(&format!("ys://{}", addr)).unwrap()
    };

    if let Some(auth) = auth {
        url.set_username(&auth.server_token()).unwrap();
    }

    let token = url.to_string();

    // Note: we need to change the scheme in string form, because changing the scheme of
    // certain Url objects is an error (https://docs.rs/url/latest/url/struct.Url.html#method.set_scheme).
    let token = if let Some(rest) = token.strip_prefix("http://") {
        format!("ys://{}", rest)
    } else if let Some(rest) = token.strip_prefix("https://") {
        format!("yss://{}", rest)
    } else {
        token
    };

    println!("Use the following connection string to connect to y-sweet:");
    println!();
    println!("   {}", token.bright_purple());
    println!();
    println!("For example, the y-sweet examples expect this connection string as an environment variable:");
    println!();
    println!("    cd examples/nextjs");
    println!(
        "    CONNECTION_STRING={} npm run dev",
        token.bright_purple()
    );
    println!();

    if auth.is_some() {
        println!(
            "{} {} {}",
            "****".bright_yellow().bold(),
            "If you are running in production, pass --prod to avoid logging this message."
                .bright_red()
                .bold(),
            "****".bright_yellow().bold(),
        );
        println!();
    }
}

pub fn print_auth_message(auth: &Authenticator) {
    println!("Run y-sweet with the following option to enable authentication:");
    println!();
    println!(
        "   {} {} {}",
        "y-sweet serve".bright_black(),
        "--auth".bright_white().bold(),
        auth.private_key().bright_blue().bold()
    );
    println!();
}
#[derive(Deserialize)]
struct SignInput {
    #[serde(rename = "docId")]
    doc_id: Option<String>,
    authorization: Option<String>,
}

#[derive(Serialize)]
struct SignOutput {
    #[serde(rename = "docId")]
    doc_id: String,
    token: String,
    authorization: Authorization,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(rename = "baseUrl", skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
}

#[derive(Serialize)]
struct VerifyOutput {
    token: TokenInfo,
    verification: VerificationResult,
}

#[derive(Serialize)]
struct TokenInfo {
    payload: serde_json::Value,
    raw: String,
}

#[derive(Serialize)]
struct VerificationResult {
    valid: bool,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "docId")]
    doc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub async fn sign_stdin(auth: &Authenticator) -> anyhow::Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut buffer = String::new();
    stdin.read_to_string(&mut buffer).await?;

    let input: SignInput = serde_json::from_str(&buffer)?;

    let doc_id = input
        .doc_id
        .ok_or_else(|| anyhow::anyhow!("docId is required"))?;

    let authorization = match input.authorization.as_deref() {
        Some("read") => Authorization::ReadOnly,
        Some("full") => Authorization::Full,
        Some(other) => anyhow::bail!("Invalid authorization: {}. Must be 'read' or 'full'", other),
        None => Authorization::Full,
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;
    let expiration = y_sweet_core::auth::ExpirationTimeEpochMillis(
        current_time + (y_sweet_core::auth::DEFAULT_EXPIRATION_SECONDS * 1000),
    );

    let token = auth.gen_doc_token(&doc_id, authorization.clone(), expiration);

    let (url, base_url) = if let Ok(prefix_url) = std::env::var("Y_SWEET_PREFIX_URL") {
        let prefix_url = Url::parse(&prefix_url)?;
        let mut ws_url = prefix_url.clone();
        ws_url
            .set_scheme(if prefix_url.scheme() == "https" {
                "wss"
            } else {
                "ws"
            })
            .map_err(|_| anyhow::anyhow!("Failed to set websocket scheme"))?;
        ws_url = ws_url.join(&format!("/d/{}/ws", doc_id))?;

        let mut base_url = prefix_url;
        if !base_url.as_str().ends_with('/') {
            base_url = base_url.join("/")?;
        }
        base_url = base_url.join(&format!("d/{}", doc_id))?;

        (Some(ws_url.to_string()), Some(base_url.to_string()))
    } else {
        (None, None)
    };

    let output = SignOutput {
        url,
        base_url,
        doc_id,
        token,
        authorization,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub async fn verify_stdin(auth: &Authenticator, doc_id: Option<&str>) -> anyhow::Result<()> {
    let mut stdin = tokio::io::stdin();
    let mut token = String::new();
    stdin.read_to_string(&mut token).await?;
    let token = token.trim();

    // Try to decode the token regardless of verification
    let decoded_payload = match auth.decode_token(token) {
        Ok(payload) => serde_json::to_value(payload)?,
        Err(_) => serde_json::Value::Null,
    };

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    let verification = match auth.verify_server_token(token, current_time) {
        Ok(()) => VerificationResult {
            valid: true,
            kind: "server".to_string(),
            authorization: None,
            doc_id: None,
            error: None,
        },
        Err(AuthError::InvalidResource) => {
            // This might be a document token
            if let Some(doc_id) = doc_id {
                match auth.verify_doc_token(token, doc_id, current_time) {
                    Ok(authorization) => {
                        let auth_str = match authorization {
                            Authorization::ReadOnly => "read",
                            Authorization::Full => "full",
                        };
                        VerificationResult {
                            valid: true,
                            kind: "document".to_string(),
                            authorization: Some(auth_str.to_string()),
                            doc_id: Some(doc_id.to_string()),
                            error: None,
                        }
                    }
                    Err(e) => VerificationResult {
                        valid: false,
                        kind: "document".to_string(),
                        authorization: None,
                        doc_id: Some(doc_id.to_string()),
                        error: Some(e.to_string()),
                    },
                }
            } else {
                VerificationResult {
                    valid: false,
                    kind: "unknown".to_string(),
                    authorization: None,
                    doc_id: None,
                    error: Some("No docId provided for document token verification".to_string()),
                }
            }
        }
        Err(e) => VerificationResult {
            valid: false,
            kind: "server".to_string(),
            authorization: None,
            doc_id: None,
            error: Some(e.to_string()),
        },
    };

    let output = VerifyOutput {
        token: TokenInfo {
            payload: decoded_payload,
            raw: token.to_string(),
        },
        verification,
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
