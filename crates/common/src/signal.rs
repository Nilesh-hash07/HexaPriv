use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const KDF_INFO_ROOT: &[u8] = b"HexaprivSignalRootKDFv1";
const KDF_INFO_CHAIN_NEXT: &[u8] = b"HexaprivSignalChainNextKeyv1";
const KDF_INFO_MESSAGE_KEY: &[u8] = b"HexaprivSignalMessageKeyv1";

/// Double Ratchet Message Header.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RatchetHeader {
    pub dh_pubkey_hex: String,
    pub pn: u32, // Previous chain length
    pub n: u32,  // Message number in current chain
}

/// Encrypted message payload incorporating Signal Double Ratchet header.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedRatchetMessage {
    pub header: RatchetHeader,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

/// In-memory Double Ratchet state for a peer conversation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    pub conversation_id: String,
    #[zeroize(skip)]
    pub dh_self_pub_hex: String,
    pub dh_self_secret_bytes: [u8; 32],
    #[zeroize(skip)]
    pub dh_remote_pub_hex: Option<String>,
    pub root_key: [u8; 32],
    pub chain_key_send: Option<[u8; 32]>,
    pub chain_key_recv: Option<[u8; 32]>,
    pub n_send: u32,
    pub n_recv: u32,
    pub pn: u32,
    #[zeroize(skip)]
    pub skipped_message_keys: HashMap<(String, u32), [u8; 32]>,
}

impl RatchetState {
    /// Initializes Alice (initiator) who knows Bob's ratchet public key.
    pub fn init_alice(
        conversation_id: &str,
        alice_secret_bytes: [u8; 32],
        bob_pubkey_bytes: [u8; 32],
        shared_secret_seed: &[u8],
    ) -> Result<Self, String> {
        let alice_secret = StaticSecret::from(alice_secret_bytes);
        let alice_pub = X25519PublicKey::from(&alice_secret);
        let bob_pub = X25519PublicKey::from(bob_pubkey_bytes);

        // Perform initial DH exchange
        let dh_output = alice_secret.diffie_hellman(&bob_pub);

        // Derive initial root key and sending chain key
        let mut salt = [0u8; 32];
        if shared_secret_seed.len() >= 32 {
            salt.copy_from_slice(&shared_secret_seed[..32]);
        }
        let hk = Hkdf::<Sha256>::new(Some(&salt), dh_output.as_bytes());
        
        let mut okm = [0u8; 64];
        hk.expand(KDF_INFO_ROOT, &mut okm)
            .map_err(|e| format!("HKDF expand error: {}", e))?;

        let mut root_key = [0u8; 32];
        let mut chain_key_send = [0u8; 32];
        root_key.copy_from_slice(&okm[..32]);
        chain_key_send.copy_from_slice(&okm[32..64]);

        Ok(Self {
            conversation_id: conversation_id.to_string(),
            dh_self_pub_hex: hex::encode(alice_pub.as_bytes()),
            dh_self_secret_bytes: alice_secret_bytes,
            dh_remote_pub_hex: Some(hex::encode(bob_pub.as_bytes())),
            root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped_message_keys: HashMap::new(),
        })
    }

    /// Initializes Bob (responder) waiting for Alice's first message header.
    pub fn init_bob(
        conversation_id: &str,
        bob_secret_bytes: [u8; 32],
        shared_secret_seed: &[u8],
    ) -> Self {
        let bob_secret = StaticSecret::from(bob_secret_bytes);
        let bob_pub = X25519PublicKey::from(&bob_secret);

        let mut root_key = [0u8; 32];
        if shared_secret_seed.len() >= 32 {
            root_key.copy_from_slice(&shared_secret_seed[..32]);
        } else {
            let hk = Hkdf::<Sha256>::new(None, shared_secret_seed);
            let _ = hk.expand(KDF_INFO_ROOT, &mut root_key);
        }

        Self {
            conversation_id: conversation_id.to_string(),
            dh_self_pub_hex: hex::encode(bob_pub.as_bytes()),
            dh_self_secret_bytes: bob_secret_bytes,
            dh_remote_pub_hex: None,
            root_key,
            chain_key_send: None,
            chain_key_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Derives next message key from sending/receiving chain.
    fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(chain_key), b"HexaprivKDFChainStep");
        let mut next_ck = [0u8; 32];
        let mut mk = [0u8; 32];
        let _ = hk.expand(KDF_INFO_CHAIN_NEXT, &mut next_ck);
        let _ = hk.expand(KDF_INFO_MESSAGE_KEY, &mut mk);
        (next_ck, mk)
    }

    /// Performs Diffie-Hellman Ratchet step when remote DH key updates.
    fn dh_ratchet(&mut self, remote_dh_pub_bytes: [u8; 32]) -> Result<(), String> {
        let remote_pub = X25519PublicKey::from(remote_dh_pub_bytes);
        self.pn = self.n_send;
        self.n_send = 0;
        self.n_recv = 0;
        self.dh_remote_pub_hex = Some(hex::encode(remote_dh_pub_bytes));

        // DH step 1: Recv Chain update
        let self_secret = StaticSecret::from(self.dh_self_secret_bytes);
        let dh_recv = self_secret.diffie_hellman(&remote_pub);
        
        let hk1 = Hkdf::<Sha256>::new(Some(&self.root_key), dh_recv.as_bytes());
        let mut okm1 = [0u8; 64];
        hk1.expand(KDF_INFO_ROOT, &mut okm1)
            .map_err(|e| format!("HKDF expand error: {}", e))?;

        self.root_key.copy_from_slice(&okm1[..32]);
        let mut ck_recv = [0u8; 32];
        ck_recv.copy_from_slice(&okm1[32..64]);
        self.chain_key_recv = Some(ck_recv);

        // DH step 2: Generate new self DH keypair & Send Chain update
        let mut csprng = rand::rngs::OsRng;
        let new_self_secret = StaticSecret::random_from_rng(&mut csprng);
        let new_self_pub = X25519PublicKey::from(&new_self_secret);

        let dh_send = new_self_secret.diffie_hellman(&remote_pub);
        let hk2 = Hkdf::<Sha256>::new(Some(&self.root_key), dh_send.as_bytes());
        let mut okm2 = [0u8; 64];
        hk2.expand(KDF_INFO_ROOT, &mut okm2)
            .map_err(|e| format!("HKDF expand error: {}", e))?;

        self.root_key.copy_from_slice(&okm2[..32]);
        let mut ck_send = [0u8; 32];
        ck_send.copy_from_slice(&okm2[32..64]);
        self.chain_key_send = Some(ck_send);

        self.dh_self_secret_bytes = new_self_secret.to_bytes();
        self.dh_self_pub_hex = hex::encode(new_self_pub.as_bytes());

        Ok(())
    }

    /// Encrypts plaintext using Double Ratchet algorithm.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedRatchetMessage, String> {
        let ck_send = match self.chain_key_send {
            Some(ck) => ck,
            None => return Err("Sending chain key not initialized".to_string()),
        };

        let (next_ck, mk) = Self::kdf_chain(&ck_send);
        self.chain_key_send = Some(next_ck);

        let header = RatchetHeader {
            dh_pubkey_hex: self.dh_self_pub_hex.clone(),
            pn: self.pn,
            n: self.n_send,
        };
        self.n_send += 1;

        let cipher = ChaCha20Poly1305::new_from_slice(&mk)
            .map_err(|e| format!("Cipher init error: {}", e))?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Double Ratchet encrypt error: {}", e))?;

        Ok(EncryptedRatchetMessage {
            header,
            nonce_hex: hex::encode(nonce_bytes),
            ciphertext_hex: hex::encode(ciphertext),
        })
    }

    /// Decrypts encrypted Signal Double Ratchet message.
    pub fn decrypt(&mut self, msg: &EncryptedRatchetMessage) -> Result<Vec<u8>, String> {
        let remote_dh_bytes = hex::decode(&msg.header.dh_pubkey_hex)
            .map_err(|e| format!("Invalid remote DH hex: {}", e))?;
        if remote_dh_bytes.len() != 32 {
            return Err("Invalid DH key length".to_string());
        }
        let mut remote_dh_arr = [0u8; 32];
        remote_dh_arr.copy_from_slice(&remote_dh_bytes);

        // Check if message key was skipped and cached previously
        let key_id = (msg.header.dh_pubkey_hex.clone(), msg.header.n);
        if let Some(mk) = self.skipped_message_keys.remove(&key_id) {
            return self.decrypt_with_key(&mk, msg);
        }

        // Check if DH ratchet is required
        let is_new_dh = match &self.dh_remote_pub_hex {
            Some(curr) => curr != &msg.header.dh_pubkey_hex,
            None => true,
        };

        if is_new_dh {
            // Skip unreceived message keys in current receiving chain if any
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet(remote_dh_arr)?;
        }

        self.skip_message_keys(msg.header.n)?;

        let ck_recv = self.chain_key_recv.ok_or("Receiving chain not set")?;
        let (next_ck, mk) = Self::kdf_chain(&ck_recv);
        self.chain_key_recv = Some(next_ck);
        self.n_recv += 1;

        self.decrypt_with_key(&mk, msg)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), String> {
        if self.n_recv + 2000 < until {
            return Err("Too many missed messages".to_string());
        }
        if let (Some(ck), Some(remote_pub)) = (&self.chain_key_recv, &self.dh_remote_pub_hex) {
            let mut current_ck = *ck;
            while self.n_recv < until {
                let (next_ck, mk) = Self::kdf_chain(&current_ck);
                self.skipped_message_keys.insert((remote_pub.clone(), self.n_recv), mk);
                current_ck = next_ck;
                self.n_recv += 1;
            }
            self.chain_key_recv = Some(current_ck);
        }
        Ok(())
    }

    fn decrypt_with_key(&self, mk: &[u8; 32], msg: &EncryptedRatchetMessage) -> Result<Vec<u8>, String> {
        let nonce_bytes = hex::decode(&msg.nonce_hex)
            .map_err(|e| format!("Invalid nonce hex: {}", e))?;
        let ciphertext = hex::decode(&msg.ciphertext_hex)
            .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;

        let cipher = ChaCha20Poly1305::new_from_slice(mk)
            .map_err(|e| format!("Cipher init error: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| "Signal Double Ratchet decryption authentication failed".to_string())
    }
}
