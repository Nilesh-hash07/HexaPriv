use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// In-memory Ephemeral Key Pair for Diffie-Hellman message encryption.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralSessionKey {
    pub secret_bytes: [u8; 32],
    #[zeroize(skip)]
    pub public_key_hex: String,
}

impl EphemeralSessionKey {
    /// Generates a new ephemeral X25519 key pair.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut rng);
        let public = X25519PublicKey::from(&secret);
        
        let secret_bytes: [u8; 32] = unsafe { std::mem::transmute(secret) };
        let public_key_hex = hex::encode(public.as_bytes());

        EphemeralSessionKey {
            secret_bytes,
            public_key_hex,
        }
    }
}

/// Encrypted message package containing ciphertext, nonce, and ephemeral public key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedPackage {
    pub ephemeral_public_key_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// Encrypts plaintext message using X25519 Diffie-Hellman DH + ChaCha20Poly1305.
pub fn encrypt_ephemeral(
    recipient_dh_pubkey_hex: &str,
    plaintext: &str,
) -> Result<EncryptedPackage, String> {
    let mut rng = rand::rngs::OsRng;
    
    // Recipient X25519 public key (32 bytes = 64 hex characters)
    let recipient_bytes = hex::decode(recipient_dh_pubkey_hex)
        .map_err(|e| format!("Invalid recipient public key hex: {}", e))?;
    if recipient_bytes.len() != 32 {
        return Err("Recipient public key must be 32 bytes (64 hex characters)".to_string());
    }
    
    let mut rec_arr = [0u8; 32];
    rec_arr.copy_from_slice(&recipient_bytes);
    let recipient_x25519_pub = X25519PublicKey::from(rec_arr);

    // Ephemeral DH key generation
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

    // Perform DH exchange
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519_pub);
    let mut shared_bytes = *shared_secret.as_bytes();

    // Initialize ChaCha20Poly1305 with shared key
    let cipher = ChaCha20Poly1305::new_from_slice(&shared_bytes)
        .map_err(|e| format!("ChaCha20 init error: {}", e))?;

    shared_bytes.zeroize();

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext_bytes = plaintext.as_bytes().to_vec();
    let ciphertext = cipher
        .encrypt(nonce, plaintext_bytes.as_ref())
        .map_err(|e| format!("Message encryption error: {}", e))?;

    plaintext_bytes.zeroize();

    Ok(EncryptedPackage {
        ephemeral_public_key_hex: hex::encode(ephemeral_pub.as_bytes()),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

/// Decrypts ciphertext package using recipient's private key (converted to X25519 static secret).
pub fn decrypt_ephemeral(
    recipient_secret_key_bytes: &[u8; 32],
    package: &EncryptedPackage,
) -> Result<String, String> {
    let ephemeral_pub_bytes = hex::decode(&package.ephemeral_public_key_hex)
        .map_err(|e| format!("Invalid ephemeral public key hex: {}", e))?;
    if ephemeral_pub_bytes.len() != 32 {
        return Err("Invalid ephemeral key length".to_string());
    }

    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(&ephemeral_pub_bytes);
    let ephemeral_pub = X25519PublicKey::from(eph_arr);

    let recipient_static = StaticSecret::from(*recipient_secret_key_bytes);
    let shared_secret = recipient_static.diffie_hellman(&ephemeral_pub);
    let mut shared_bytes = *shared_secret.as_bytes();

    let cipher = ChaCha20Poly1305::new_from_slice(&shared_bytes)
        .map_err(|e| format!("ChaCha20 init error: {}", e))?;
    
    shared_bytes.zeroize();

    let nonce_bytes = hex::decode(&package.nonce_hex)
        .map_err(|e| format!("Invalid nonce hex: {}", e))?;
    let ciphertext = hex::decode(&package.ciphertext_hex)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut decrypted_bytes = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "Decryption failed: Ephemeral key missing or invalid".to_string())?;

    let plaintext = String::from_utf8(decrypted_bytes.clone())
        .map_err(|e| format!("UTF-8 decode error: {}", e))?;

    decrypted_bytes.zeroize();

    Ok(plaintext)
}
