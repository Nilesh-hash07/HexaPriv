use privacy_common::identity::EncryptedIdentityFile;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Storage {
    pub base_dir: PathBuf,
}

impl Storage {
    pub fn new() -> Result<Self, String> {
        let home = dirs_home().ok_or_else(|| "Could not determine home directory".to_string())?;
        let base_dir = home.join(".secure-messenger");

        let storage = Storage { base_dir };
        storage.ensure_directories()?;
        Ok(storage)
    }

    pub fn with_custom_path(base_dir: PathBuf) -> Result<Self, String> {
        let storage = Storage { base_dir };
        storage.ensure_directories()?;
        Ok(storage)
    }

    fn ensure_directories(&self) -> Result<(), String> {
        fs::create_dir_all(&self.base_dir)
            .map_err(|e| format!("Failed to create base dir: {}", e))?;
        fs::create_dir_all(self.base_dir.join("ephemeral"))
            .map_err(|e| format!("Failed to create ephemeral dir: {}", e))?;
        fs::create_dir_all(self.base_dir.join("messages"))
            .map_err(|e| format!("Failed to create messages dir: {}", e))?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.base_dir, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }

    pub fn identity_exists(&self) -> bool {
        self.base_dir.join("identity").exists() && self.base_dir.join("config").exists()
    }

    pub fn save_identity(&self, encrypted_file: &EncryptedIdentityFile) -> Result<(), String> {
        let path = self.base_dir.join("identity");
        let content = serde_json::to_string_pretty(encrypted_file)
            .map_err(|e| format!("JSON serialize error: {}", e))?;
        self.write_secure_file(&path, content.as_bytes())
    }

    pub fn load_identity(&self) -> Result<EncryptedIdentityFile, String> {
        let path = self.base_dir.join("identity");
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read identity file: {}", e))?;
        serde_json::from_str(&content).map_err(|e| format!("Invalid identity file format: {}", e))
    }

    pub fn write_secure_file(&self, path: &Path, content: &[u8]) -> Result<(), String> {
        let mut file = File::create(path).map_err(|e| format!("File creation failed: {}", e))?;
        file.write_all(content).map_err(|e| format!("File write failed: {}", e))?;
        file.flush().map_err(|e| format!("File flush failed: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Complete silent wipe of all data in base_dir.
    pub fn silent_wipe(&self) -> Result<(), String> {
        if self.base_dir.exists() {
            // Overwrite files with zeroes before unlinking for forensic protection
            let _ = self.overwrite_dir_contents(&self.base_dir);
            let _ = fs::remove_dir_all(&self.base_dir);
        }
        Ok(())
    }

    fn overwrite_dir_contents(&self, dir: &Path) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    let _ = self.overwrite_dir_contents(&path);
                } else if path.is_file() {
                    if let Ok(metadata) = fs::metadata(&path) {
                        let len = metadata.len() as usize;
                        let zero_buffer = vec![0u8; len];
                        let _ = fs::write(&path, &zero_buffer);
                    }
                }
            }
        }
        Ok(())
    }

    /// Removes all local ephemeral keys and messages for a specific conversation ID.
    pub fn delete_conversation_keys(&self, conversation_id: &str) -> Result<(), String> {
        let eph_dir = self.base_dir.join("ephemeral").join(conversation_id);
        let msg_dir = self.base_dir.join("messages").join(conversation_id);

        if eph_dir.exists() {
            let _ = self.overwrite_dir_contents(&eph_dir);
            let _ = fs::remove_dir_all(eph_dir);
        }
        if msg_dir.exists() {
            let _ = self.overwrite_dir_contents(&msg_dir);
            let _ = fs::remove_dir_all(msg_dir);
        }
        Ok(())
    }

    pub fn save_message(&self, conversation_id: &str, msg_id: &str, content: &str) -> Result<(), String> {
        let msg_dir = self.base_dir.join("messages").join(conversation_id);
        fs::create_dir_all(&msg_dir).map_err(|e| format!("Failed to create conv dir: {}", e))?;
        
        let path = msg_dir.join(format!("{}.txt", msg_id));
        self.write_secure_file(&path, content.as_bytes())
    }

    pub fn list_messages(&self, conversation_id: &str) -> Result<Vec<(String, String)>, String> {
        let msg_dir = self.base_dir.join("messages").join(conversation_id);
        if !msg_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let entries = fs::read_dir(&msg_dir).map_err(|e| format!("Read dir error: {}", e))?;
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let filename = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
                        messages.push((filename, content));
                    }
                }
            }
        }
        messages.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(messages)
    }

    pub fn list_conversations(&self) -> Result<Vec<String>, String> {
        let msg_dir = self.base_dir.join("messages");
        if !msg_dir.exists() {
            return Ok(Vec::new());
        }

        let mut convs = Vec::new();
        let entries = fs::read_dir(&msg_dir).map_err(|e| format!("Read dir error: {}", e))?;
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    convs.push(path.file_name().unwrap_or_default().to_string_lossy().to_string());
                }
            }
        }
        Ok(convs)
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
