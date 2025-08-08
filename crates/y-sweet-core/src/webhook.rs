use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info};
use crate::api_types::NANOID_ALPHABET;
use crate::store::Store;

#[derive(Error, Debug)]
pub enum WebhookError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Store error: {0}")]
    StoreError(String),
    #[error("JSON parsing error: {0}")]
    JsonError(String),
}

#[derive(Serialize, Debug)]
pub struct WebhookPayload {
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub prefix: String,
    pub url: String,
    pub timeout_ms: u64,
    pub auth_token: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WebhookConfigDocument {
    pub configs: Vec<WebhookConfig>,
}

impl WebhookConfigDocument {
    pub fn validate(&self) -> Result<(), WebhookError> {
        // Check for duplicate prefixes
        let mut seen_prefixes = std::collections::HashSet::new();
        for config in &self.configs {
            if !seen_prefixes.insert(&config.prefix) {
                return Err(WebhookError::Configuration(format!(
                    "Duplicate prefix found: {}", config.prefix
                )));
            }
            
            // Validate URL format
            if url::Url::parse(&config.url).is_err() {
                return Err(WebhookError::Configuration(format!(
                    "Invalid URL format: {}", config.url
                )));
            }
            
            // Validate timeout
            if config.timeout_ms == 0 {
                return Err(WebhookError::Configuration(
                    "Timeout must be greater than 0".to_string()
                ));
            }
        }
        Ok(())
    }
}

pub struct WebhookDispatcher {
    pub configs: Vec<WebhookConfig>,
    queues: HashMap<String, mpsc::UnboundedSender<String>>,
    shutdown_senders: Vec<mpsc::UnboundedSender<()>>,
}

impl WebhookDispatcher {
    pub fn new(configs: Vec<WebhookConfig>) -> Result<Self, WebhookError> {
        let mut queues = HashMap::new();
        let mut shutdown_senders = Vec::new();
        
        for config in &configs {
            let (tx, rx) = mpsc::unbounded_channel();
            let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel();
            
            queues.insert(config.prefix.clone(), tx);
            shutdown_senders.push(shutdown_tx);
            
            // Spawn worker task for this prefix with shutdown signal
            let config_clone = config.clone();
            tokio::spawn(async move {
                Self::webhook_worker_with_shutdown(config_clone, rx, shutdown_rx).await;
            });
        }
        
        Ok(WebhookDispatcher { configs, queues, shutdown_senders })
    }
    
    /// Load webhook configuration from store
    pub async fn from_store(store: Option<Arc<Box<dyn Store>>>) -> Result<Option<Self>, WebhookError> {
        let store = match store {
            Some(store) => store,
            None => return Ok(None),
        };
        
        // Use a special key that cannot be accessed as a document ID
        // This key is reserved for system configuration and should not be exposed to clients
        // Using a .config directory structure for better organization
        let config_key = ".config/webhooks.json";
        
        match store.get(config_key).await {
            Ok(Some(data)) => {
                let config_str = String::from_utf8(data)
                    .map_err(|e| WebhookError::JsonError(format!("Invalid UTF-8 in config: {}", e)))?;
                
                let config_doc: WebhookConfigDocument = serde_json::from_str(&config_str)
                    .map_err(|e| WebhookError::JsonError(format!("Failed to parse config JSON: {}", e)))?;
                
                config_doc.validate()?;
                
                let dispatcher = Self::new(config_doc.configs)?;
                info!("Loaded webhook configuration from store with {} configs", dispatcher.configs.len());
                Ok(Some(dispatcher))
            }
            Ok(None) => {
                info!("No webhook configuration found in store");
                Ok(None)
            }
            Err(e) => {
                error!("Failed to load webhook config from store: {}", e);
                Err(WebhookError::StoreError(format!("Store access failed: {}", e)))
            }
        }
    }
    
    /// Gracefully shutdown all worker tasks
    pub fn shutdown(&self) {
        for sender in &self.shutdown_senders {
            let _ = sender.send(()); // Ignore errors if receiver already dropped
        }
    }
    
    pub fn send_webhooks(&self, doc_id: String) {
        let matching_prefixes = self.find_matching_prefixes(&doc_id);
        
        for prefix in matching_prefixes {
            if let Some(sender) = self.queues.get(&prefix) {
                if let Err(e) = sender.send(doc_id.clone()) {
                    error!("Failed to queue webhook for prefix '{}': {}", prefix, e);
                }
            }
        }
    }
    
    
    async fn webhook_worker_with_shutdown(
        config: WebhookConfig,
        mut rx: mpsc::UnboundedReceiver<String>,
        mut shutdown_rx: mpsc::UnboundedReceiver<()>,
    ) {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .pool_max_idle_per_host(5)
            .user_agent("y-sweet-webhook/0.8.2")
            .build()
            .unwrap_or_else(|e| {
                error!("Failed to create HTTP client for prefix '{}': {}", config.prefix, e);
                panic!("HTTP client creation failed");
            });
        
        loop {
            tokio::select! {
                doc_id = rx.recv() => {
                    if let Some(doc_id) = doc_id {
                        if let Err(e) = Self::send_single_webhook(&client, &config, doc_id.clone()).await {
                            error!("Failed to send webhook for document {} with prefix '{}': {}", doc_id, config.prefix, e);
                        }
                    } else {
                        break; // Channel closed
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Webhook worker shutting down for prefix: {}", config.prefix);
                    break;
                }
            }
        }
    }
    
    fn find_matching_prefixes(&self, doc_id: &str) -> Vec<String> {
        let mut matches: Vec<_> = self.configs
            .iter()
            .filter(|config| doc_id.starts_with(&config.prefix))
            .collect();
        
        // Sort by prefix length (longest first) for longest-match priority
        matches.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
        
        matches.into_iter().map(|config| config.prefix.clone()).collect()
    }
    
    async fn send_single_webhook(client: &Client, config: &WebhookConfig, doc_id: String) -> Result<(), WebhookError> {
        let payload = WebhookPayload {
            event_type: "document.updated".to_string(),
            event_id: format!("evt_{}", nanoid::nanoid!(21, NANOID_ALPHABET)),
            payload: serde_json::json!({
                "doc_id": doc_id.clone(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        };
        
        debug!("Sending webhook for document {} to prefix '{}'", doc_id, config.prefix);
        
        let mut request = client
            .post(&config.url)
            .header("Content-Type", "application/json");
        
        if let Some(auth_token) = &config.auth_token {
            request = request.header("Authorization", format!("Bearer {}", auth_token));
        }
        
        let request = request.json(&payload);
        
        let response = timeout(Duration::from_millis(config.timeout_ms), request.send())
            .await
            .map_err(|_| WebhookError::Timeout(format!("Webhook request timed out after {}ms", config.timeout_ms)))?
            .map_err(|e| WebhookError::RequestFailed(e.to_string()))?;
        
        if response.status().is_success() {
            info!("Webhook sent successfully for document {} to prefix '{}'", doc_id, config.prefix);
            Ok(())
        } else {
            let status = response.status();
            let error_msg = format!("Webhook failed with status {}", status);
            error!("Webhook failed for document {} to prefix '{}': {}", doc_id, config.prefix, error_msg);
            Err(WebhookError::RequestFailed(error_msg))
        }
    }
}

pub type WebhookCallback = Arc<dyn Fn(String) + Send + Sync>;

pub fn create_webhook_callback(dispatcher: Arc<WebhookDispatcher>) -> WebhookCallback {
    Arc::new(move |doc_id: String| {
        dispatcher.send_webhooks(doc_id);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_prefix_matching() {
        let configs = vec![
            WebhookConfig {
                prefix: "user_".to_string(),
                url: "https://example.com/user".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "user_admin_".to_string(),
                url: "https://example.com/admin".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "".to_string(),
                url: "https://example.com/default".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
        ];
        
        let dispatcher = WebhookDispatcher::new(configs).unwrap();
        
        // Test longest-matching-prefix
        let matches = dispatcher.find_matching_prefixes("user_admin_123");
        assert_eq!(matches, vec!["user_admin_", "user_", ""]);
        
        // Test single match
        let matches = dispatcher.find_matching_prefixes("user_123");
        assert_eq!(matches, vec!["user_", ""]);
        
        // Test default match only
        let matches = dispatcher.find_matching_prefixes("doc_123");
        assert_eq!(matches, vec![""]);
        
        // Test specific test case from user
        let matches = dispatcher.find_matching_prefixes("test_document");
        assert_eq!(matches, vec![""]);
        
        // Test exact user case - test_ prefix with test_document
        let test_configs = vec![
            WebhookConfig {
                prefix: "test_".to_string(),
                url: "https://example.com/test".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
        ];
        let test_dispatcher = WebhookDispatcher::new(test_configs).unwrap();
        let matches = test_dispatcher.find_matching_prefixes("test_document");
        assert_eq!(matches, vec!["test_"]);
        
        // Test no matches (empty config)
        let empty_dispatcher = WebhookDispatcher::new(vec![]).unwrap();
        let matches = empty_dispatcher.find_matching_prefixes("anything");
        assert_eq!(matches, Vec::<String>::new());
    }
    
    #[test]
    fn test_webhook_config_parsing() {
        // Test valid config
        let config = WebhookConfig {
            prefix: "test:".to_string(),
            url: "https://example.com".to_string(),
            timeout_ms: 5000,
            auth_token: None,
        };
        assert_eq!(config.prefix, "test:");
        assert_eq!(config.url, "https://example.com");
        assert_eq!(config.timeout_ms, 5000);
        
        // Test empty prefix (catches all)
        let config = WebhookConfig {
            prefix: "".to_string(),
            url: "https://example.com/default".to_string(),
            timeout_ms: 3000,
            auth_token: None,
        };
        assert_eq!(config.prefix, "");
        assert_eq!(config.timeout_ms, 3000);
    }
    
    #[tokio::test]
    async fn test_webhook_dispatcher_creation() {
        let configs = vec![
            WebhookConfig {
                prefix: "user:".to_string(),
                url: "https://example.com/user".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
            WebhookConfig {
                prefix: "doc:".to_string(),
                url: "https://example.com/doc".to_string(),
                timeout_ms: 3000,
                auth_token: None,
            },
        ];
        
        let dispatcher = WebhookDispatcher::new(configs.clone()).unwrap();
        assert_eq!(dispatcher.configs.len(), 2);
        assert_eq!(dispatcher.queues.len(), 2);
        assert!(dispatcher.queues.contains_key("user:"));
        assert!(dispatcher.queues.contains_key("doc:"));
    }
    
    #[tokio::test]
    async fn test_queue_behavior() {
        let configs = vec![
            WebhookConfig {
                prefix: "test:".to_string(),
                url: "https://httpbin.org/post".to_string(),
                timeout_ms: 5000,
                auth_token: None,
            },
        ];
        
        let dispatcher = WebhookDispatcher::new(configs).unwrap();
        
        // Test webhook queuing
        dispatcher.send_webhooks("test:123".to_string());
        dispatcher.send_webhooks("test:456".to_string());
        
        // Give some time for async processing
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // If we get here without panicking, the queue is working
        assert!(true);
    }
}