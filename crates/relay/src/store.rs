use privacy_common::protocol::{EncryptedMessageBlob, KeyDestructionSignal};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SECONDS: u64 = 86400; // 24 Hours TTL

#[derive(Clone, Default)]
pub struct MemoryStore {
    // Map recipient public key -> pending encrypted message blobs
    messages: Arc<Mutex<HashMap<String, Vec<EncryptedMessageBlob>>>>,
    // Map recipient public key -> pending key destruction signals
    signals: Arc<Mutex<HashMap<String, Vec<KeyDestructionSignal>>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        MemoryStore::default()
    }

    /// Stores an encrypted message blob for recipient. Purges expired messages.
    pub fn add_message(&self, blob: EncryptedMessageBlob) {
        let mut map = self.messages.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let list = map.entry(blob.recipient_pubkey.clone()).or_insert_with(Vec::new);
        list.retain(|m| now.saturating_sub(m.created_at) < TTL_SECONDS);
        list.push(blob);
    }

    /// Fetches and removes pending messages for a recipient (blind queue drain).
    pub fn fetch_messages(&self, recipient_pubkey: &str) -> Vec<EncryptedMessageBlob> {
        let mut map = self.messages.lock().unwrap();
        if let Some(list) = map.remove(recipient_pubkey) {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            list.into_iter()
                .filter(|m| now.saturating_sub(m.created_at) < TTL_SECONDS)
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Processes a key destruction signal.
    /// 1. Purges any pending messages matching conversation_id from memory store.
    /// 2. Queues signal for sender and recipient.
    pub fn process_destruction_signal(&self, signal: KeyDestructionSignal) {
        let mut msgs_map = self.messages.lock().unwrap();
        for list in msgs_map.values_mut() {
            list.retain(|m| m.conversation_id != signal.conversation_id);
        }

        let mut sigs_map = self.signals.lock().unwrap();
        // Route signal to all participants or broadcast
        sigs_map
            .entry(signal.requester_pubkey.clone())
            .or_insert_with(Vec::new)
            .push(signal.clone());
        
        // Also place in wildcard store for recipient retrieval
        sigs_map
            .entry("broadcast".to_string())
            .or_insert_with(Vec::new)
            .push(signal);
    }

    /// Fetches pending key destruction signals for a recipient.
    pub fn fetch_signals(&self, recipient_pubkey: &str) -> Vec<KeyDestructionSignal> {
        let mut map = self.signals.lock().unwrap();
        let mut result = Vec::new();

        if let Some(list) = map.remove(recipient_pubkey) {
            result.extend(list);
        }
        if let Some(list) = map.get_mut("broadcast") {
            let filtered: Vec<KeyDestructionSignal> = list
                .drain(..)
                .filter(|s| s.requester_pubkey != recipient_pubkey)
                .collect();
            result.extend(filtered);
        }
        result
    }
}
