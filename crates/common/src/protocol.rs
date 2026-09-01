use serde::{Deserialize, Serialize};

/// Payload sent over the network when transmitting an encrypted message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessageBlob {
    pub message_id: String,
    pub conversation_id: String,
    pub recipient_pubkey: String,
    pub sender_pubkey: String,
    pub ephemeral_pubkey: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: u64,
}

/// Signal payload sent over network to initiate ephemeral key destruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDestructionSignal {
    pub conversation_id: String,
    pub requester_pubkey: String,
    pub signature: String,
    pub timestamp: u64,
}

/// API Response envelope for relay server requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

/// Utility function to sanitize string input to ASCII-only.
pub fn sanitize_ascii(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii()).collect()
}

/// Computes SHA-256 fingerprint for a public key hex string.
pub fn compute_fingerprint(pubkey_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey_hex.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
