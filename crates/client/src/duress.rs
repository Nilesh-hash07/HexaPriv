use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Duration;
use zeroize::Zeroize;

use crate::storage::Storage;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfigFile {
    pub real_code_hash: String,
    pub duress_code_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthResult {
    Real,
    DuressTriggered,
}

pub struct DuressEngine<'a> {
    storage: &'a Storage,
}

impl<'a> DuressEngine<'a> {
    pub fn new(storage: &'a Storage) -> Self {
        DuressEngine { storage }
    }

    /// Sets up real passcode (Code A) and duress passcode (Code B).
    pub fn setup_passcodes(&self, real_code: &str, duress_code: &str) -> Result<(), String> {
        if real_code == duress_code {
            return Err("Real code and duress code must be different".to_string());
        }

        let argon2 = Argon2::default();

        let salt_a = SaltString::generate(&mut OsRng);
        let mut real_bytes = real_code.as_bytes().to_vec();
        let hash_a = argon2
            .hash_password(&real_bytes, &salt_a)
            .map_err(|e| format!("Argon2 hash error A: {}", e))?
            .to_string();
        real_bytes.zeroize();

        let salt_b = SaltString::generate(&mut OsRng);
        let mut duress_bytes = duress_code.as_bytes().to_vec();
        let hash_b = argon2
            .hash_password(&duress_bytes, &salt_b)
            .map_err(|e| format!("Argon2 hash error B: {}", e))?
            .to_string();
        duress_bytes.zeroize();

        let config = ConfigFile {
            real_code_hash: hash_a,
            duress_code_hash: hash_b,
        };

        let path = self.storage.base_dir.join("config");
        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| format!("Config serialize error: {}", e))?;
        self.storage.write_secure_file(&path, json.as_bytes())
    }

    /// Verifies input passcode against stored Argon2id hashes.
    pub fn authenticate(&self, input_code: &str) -> Result<AuthResult, String> {
        let config_path = self.storage.base_dir.join("config");
        let json = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;
        let config: ConfigFile = serde_json::from_str(&json)
            .map_err(|e| format!("Config parse error: {}", e))?;

        let argon2 = Argon2::default();
        let mut input_bytes = input_code.as_bytes().to_vec();

        // Check Real Code
        if let Ok(parsed_hash) = PasswordHash::new(&config.real_code_hash) {
            if argon2.verify_password(&input_bytes, &parsed_hash).is_ok() {
                input_bytes.zeroize();
                return Ok(AuthResult::Real);
            }
        }

        // Check Duress Code
        if let Ok(parsed_hash) = PasswordHash::new(&config.duress_code_hash) {
            if argon2.verify_password(&input_bytes, &parsed_hash).is_ok() {
                input_bytes.zeroize();
                #[cfg(not(test))]
                {
                    self.trigger_duress_wipe()?;
                }
                #[cfg(test)]
                {
                    let _ = self.storage.silent_wipe();
                }
                return Ok(AuthResult::DuressTriggered);
            }
        }

        input_bytes.zeroize();
        Err("Authentication failed: Invalid code".to_string())
    }

    /// Triggers silent wipe, shows decoy interface, waits 5s, and crashes.
    pub fn trigger_duress_wipe(&self) -> Result<(), String> {
        // 1. Silent, immediate wipe of files
        let _ = self.storage.silent_wipe();

        // 2. Render decoy interface
        println!("\x1B[2J\x1B[3J\x1B[H"); // Clear screen
        println!("============================================================");
        println!(" PRIVACY TEXT - TERMINAL MESSENGER v1.0                     ");
        println!(" Status: Connected to relay server                           ");
        println!("============================================================");
        println!(" [System Info] No active conversations found.");
        println!(" [System Info] Syncing message store...");
        println!(" Command: /help for assistance");
        println!(" > ");

        // 3. Sleep 5 seconds and exit with crash code
        thread::sleep(Duration::from_secs(5));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_passcode_setup_and_auth() {
        let dir = tempdir().unwrap();
        let storage = Storage::with_custom_path(dir.path().to_path_buf()).unwrap();
        let engine = DuressEngine::new(&storage);

        engine.setup_passcodes("RealCode123", "WipeCode999").unwrap();

        // Test real code
        let auth = engine.authenticate("RealCode123").unwrap();
        assert_eq!(auth, AuthResult::Real);

        // Test duress code (wipes directory)
        let auth_duress = engine.authenticate("WipeCode999").unwrap();
        assert_eq!(auth_duress, AuthResult::DuressTriggered);
        assert!(!dir.path().join("config").exists());

        // Invalid code test
        let err = engine.authenticate("WrongCode");
        assert!(err.is_err());
    }
}
