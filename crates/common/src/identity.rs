use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Container for serialized encrypted identity.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedIdentityFile {
    pub public_key_hex: String,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub encrypted_private_key_hex: String,
}

/// In-memory Identity structure holding zeroized keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    pub public_key_hex: String,
    pub secret_key_bytes: [u8; 32],
}

impl Identity {
    /// Generates a new Ed25519 identity keypair.
    pub fn generate() -> (Self, SigningKey) {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.as_bytes());
        
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(signing_key.to_bytes().as_slice());

        let identity = Identity {
            public_key_hex: pub_hex,
            secret_key_bytes: secret_bytes,
        };
        (identity, signing_key)
    }

    /// Computes matching X25519 Diffie-Hellman public key (64 hex characters).
    pub fn dh_public_key_hex(&self) -> String {
        let static_secret = StaticSecret::from(self.secret_key_bytes);
        let x25519_pub = X25519PublicKey::from(&static_secret);
        hex::encode(x25519_pub.as_bytes())
    }

    /// Encrypts identity private key using passphrase derived via Argon2id.
    pub fn encrypt(&self, passphrase: &str) -> Result<EncryptedIdentityFile, String> {
        let mut passphrase_bytes = passphrase.as_bytes().to_vec();
        
        // Generate random 16-byte salt for Argon2id
        let salt = SaltString::generate(&mut OsRng);
        
        let params = Params::new(65536, 3, 1, Some(32))
            .map_err(|e| format!("Argon2 params error: {}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(
                &passphrase_bytes,
                salt.as_str().as_bytes(),
                &mut derived_key,
            )
            .map_err(|e| format!("Argon2id key derivation failed: {}", e))?;

        passphrase_bytes.zeroize();

        // Encrypt secret_key_bytes with ChaCha20Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("ChaCha20 init error: {}", e))?;
        
        derived_key.zeroize();

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, self.secret_key_bytes.as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        Ok(EncryptedIdentityFile {
            public_key_hex: self.public_key_hex.clone(),
            salt_hex: hex::encode(salt.as_str()),
            nonce_hex: hex::encode(nonce_bytes),
            encrypted_private_key_hex: hex::encode(ciphertext),
        })
    }

    /// Decrypts identity private key using passphrase.
    pub fn decrypt(
        encrypted_file: &EncryptedIdentityFile,
        passphrase: &str,
    ) -> Result<Self, String> {
        let mut passphrase_bytes = passphrase.as_bytes().to_vec();
        let salt_str = hex::decode(&encrypted_file.salt_hex)
            .map_err(|e| format!("Invalid salt hex: {}", e))?;
        let nonce_bytes = hex::decode(&encrypted_file.nonce_hex)
            .map_err(|e| format!("Invalid nonce hex: {}", e))?;
        let ciphertext = hex::decode(&encrypted_file.encrypted_private_key_hex)
            .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

        let params = Params::new(65536, 3, 1, Some(32))
            .map_err(|e| format!("Argon2 params error: {}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut derived_key = [0u8; 32];
        argon2
            .hash_password_into(&passphrase_bytes, &salt_str, &mut derived_key)
            .map_err(|_| "Invalid passphrase or authentication failure".to_string())?;

        passphrase_bytes.zeroize();

        let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("ChaCha20 init error: {}", e))?;
        
        derived_key.zeroize();

        let nonce = Nonce::from_slice(&nonce_bytes);
        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Passphrase decryption failed or invalid key".to_string())?;

        if decrypted.len() != 32 {
            return Err("Decrypted key invalid length".to_string());
        }

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&decrypted);

        Ok(Identity {
            public_key_hex: encrypted_file.public_key_hex.clone(),
            secret_key_bytes: secret_bytes,
        })
    }

    /// Returns the SigningKey representation for signing signals.
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.secret_key_bytes)
    }
}
