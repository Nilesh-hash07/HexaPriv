pub mod ephemeral;
pub mod identity;
pub mod protocol;
pub mod signal;

pub use ephemeral::*;
pub use identity::*;
pub use protocol::*;
pub use signal::*;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_identity_generation_and_encryption() {
        let (identity, _signing_key) = Identity::generate();
        assert_eq!(identity.public_key_hex.len(), 64);

        let passphrase = "SuperSecurePassphrase123!";
        let encrypted_file = identity.encrypt(passphrase).expect("Encryption failed");

        assert_eq!(encrypted_file.public_key_hex, identity.public_key_hex);

        let decrypted_identity = Identity::decrypt(&encrypted_file, passphrase)
            .expect("Decryption failed");
        assert_eq!(decrypted_identity.public_key_hex, identity.public_key_hex);
        assert_eq!(decrypted_identity.secret_key_bytes, identity.secret_key_bytes);
    }

    #[test]
    fn test_identity_decryption_invalid_passphrase() {
        let (identity, _) = Identity::generate();
        let encrypted_file = identity.encrypt("CorrectPass").unwrap();
        let res = Identity::decrypt(&encrypted_file, "WrongPass");
        assert!(res.is_err());
    }

    #[test]
    fn test_ephemeral_encryption_decryption() {
        let (recipient_id, _) = Identity::generate();
        let message = "Secret ephemeral message for testing";

        let package = encrypt_ephemeral(&recipient_id.dh_public_key_hex(), message)
            .expect("Ephemeral encryption failed");

        let decrypted = decrypt_ephemeral(&recipient_id.secret_key_bytes, &package)
            .expect("Ephemeral decryption failed");

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_fingerprint_and_ascii_sanitization() {
        let hex_pub = "a".repeat(64);
        let fp = compute_fingerprint(&hex_pub);
        assert_eq!(fp.len(), 64);

        let raw_input = "Hello \x07World!\nTest\x00";
        let sanitized = sanitize_ascii(raw_input);
        assert_eq!(sanitized, "Hello \x07World!\nTest\x00");
    }

    #[test]
    fn test_signal_double_ratchet_conversation() {
        let alice_secret = [1u8; 32];
        let bob_secret = [2u8; 32];

        let bob_pub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(bob_secret));
        let seed = b"HexaprivTestSharedSeed123456789012345";

        let mut alice = RatchetState::init_alice("conv1", alice_secret, *bob_pub.as_bytes(), seed).unwrap();
        let mut bob = RatchetState::init_bob("conv1", bob_secret, seed);

        // Alice sends message 1 to Bob
        let msg1 = alice.encrypt(b"Hello Bob from Alice over Signal Protocol!").unwrap();
        let dec1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(String::from_utf8(dec1).unwrap(), "Hello Bob from Alice over Signal Protocol!");

        // Bob replies to Alice (triggers DH ratchet!)
        let msg2 = bob.encrypt(b"Hello Alice! Reply with forward secrecy.").unwrap();
        let dec2 = alice.decrypt(&msg2).unwrap();
        assert_eq!(String::from_utf8(dec2).unwrap(), "Hello Alice! Reply with forward secrecy.");

        // Alice sends another message
        let msg3 = alice.encrypt(b"Third message ratcheted successfully.").unwrap();
        let dec3 = bob.decrypt(&msg3).unwrap();
        assert_eq!(String::from_utf8(dec3).unwrap(), "Third message ratcheted successfully.");
    }
}

