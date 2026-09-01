use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use privacy_common::protocol::{ApiResponse, EncryptedMessageBlob, KeyDestructionSignal};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

pub mod store;
use store::MemoryStore;

pub async fn run_relay(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/send", post(send_message))
        .route("/api/v1/poll/:recipient", get(poll_messages))
        .route("/api/v1/destroy", post(destroy_keys))
        .route("/api/v1/signals/:recipient", get(poll_signals))
        .layer(cors)
        .with_state(store);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Privacy Text Relay Server running on port {} (Zero-Log Mode Enabled)", port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> (StatusCode, Json<ApiResponse<String>>) {
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Relay operational".to_string(),
            data: Some("OK".to_string()),
        }),
    )
}

async fn send_message(
    State(store): State<MemoryStore>,
    Json(blob): Json<EncryptedMessageBlob>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if blob.recipient_pubkey.len() != 64 || blob.ciphertext.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Invalid payload parameters".to_string(),
                data: None,
            }),
        );
    }

    store.add_message(blob);

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Message blob queued for delivery".to_string(),
            data: None,
        }),
    )
}

async fn poll_messages(
    State(store): State<MemoryStore>,
    Path(recipient): Path<String>,
) -> (StatusCode, Json<ApiResponse<Vec<EncryptedMessageBlob>>>) {
    let blobs = store.fetch_messages(&recipient);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Retrieved {} messages", blobs.len()),
            data: Some(blobs),
        }),
    )
}

async fn destroy_keys(
    State(store): State<MemoryStore>,
    Json(signal): Json<KeyDestructionSignal>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    if signal.conversation_id.is_empty() || signal.requester_pubkey.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse {
                success: false,
                message: "Invalid destruction signal".to_string(),
                data: None,
            }),
        );
    }

    store.process_destruction_signal(signal);

    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: "Ephemeral key destruction signal processed".to_string(),
            data: None,
        }),
    )
}

async fn poll_signals(
    State(store): State<MemoryStore>,
    Path(recipient): Path<String>,
) -> (StatusCode, Json<ApiResponse<Vec<KeyDestructionSignal>>>) {
    let signals = store.fetch_signals(&recipient);
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            message: format!("Retrieved {} destruction signals", signals.len()),
            data: Some(signals),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_store_add_poll_and_destruction() {
        let store = MemoryStore::new();
        let recipient = "a".repeat(64);
        let sender = "b".repeat(64);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let blob = EncryptedMessageBlob {
            message_id: "msg1".to_string(),
            conversation_id: "conv1".to_string(),
            recipient_pubkey: recipient.clone(),
            sender_pubkey: sender.clone(),
            ephemeral_pubkey: "c".repeat(64),
            nonce: "d".repeat(24),
            ciphertext: "e".repeat(32),
            created_at: now,
        };

        store.add_message(blob);
        let fetched = store.fetch_messages(&recipient);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].message_id, "msg1");

        // Verify empty queue after drain
        let empty = store.fetch_messages(&recipient);
        assert_eq!(empty.len(), 0);

        // Test key destruction signal purging
        let blob2 = EncryptedMessageBlob {
            message_id: "msg2".to_string(),
            conversation_id: "conv_purge".to_string(),
            recipient_pubkey: recipient.clone(),
            sender_pubkey: sender.clone(),
            ephemeral_pubkey: "c".repeat(64),
            nonce: "d".repeat(24),
            ciphertext: "e".repeat(32),
            created_at: now,
        };
        store.add_message(blob2);

        let signal = KeyDestructionSignal {
            conversation_id: "conv_purge".to_string(),
            requester_pubkey: sender.clone(),
            signature: "sig".to_string(),
            timestamp: now,
        };
        store.process_destruction_signal(signal);

        let drained = store.fetch_messages(&recipient);
        assert_eq!(drained.len(), 0);
    }
}
