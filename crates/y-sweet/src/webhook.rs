use std::{env, sync::Arc};
use y_sweet_core::{store::Store, webhook::{WebhookConfig, WebhookDispatcher, WebhookConfigDocument}};

pub fn create_webhook_dispatcher() -> Option<WebhookDispatcher> {
    let config_json = env::var("Y_SWEET_WEBHOOK_CONFIG").ok()?;
    
    let configs: Vec<WebhookConfig> = serde_json::from_str(&config_json)
        .map_err(|e| {
            tracing::error!("Failed to parse webhook config: {}", e);
            e
        })
        .ok()?;
    
    WebhookDispatcher::new(configs)
        .map_err(|e| {
            tracing::error!("Failed to create webhook dispatcher: {}", e);
            e
        })
        .ok()
}


/// Set webhook configuration in the store
pub async fn set_webhook_config_in_store(
    store: Arc<Box<dyn Store>>,
    configs: Vec<WebhookConfig>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_doc = WebhookConfigDocument { configs };
    let config_json = serde_json::to_string(&config_doc)?;
    
    // Use the same key as the loader
    let config_key = ".config/webhooks.json";
    
    store.set(config_key, config_json.into_bytes()).await?;
    println!("Webhook configuration saved to store");
    Ok(())
}