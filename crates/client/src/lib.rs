use libp2p::Multiaddr;
use privacy_common::identity::Identity;
use privacy_common::protocol::compute_fingerprint;
use privacy_common::signal::RatchetState;
use sha2::Digest;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;


pub mod duress;
pub mod p2p;
pub mod storage;
pub mod terminal;
pub mod tui;

pub use duress::{AuthResult, DuressEngine};
pub use p2p::{DirectP2pMessage, P2pCommand, P2pEvent, P2pNetworkService};
pub use storage::Storage;
pub use terminal::TerminalUI;
pub use tui::{AppState, PeerItem, TerminalApp, UiMessage};

pub async fn run_client(
    _override_relay_url: Option<String>,
    override_port: Option<u16>,
) -> Result<(), Box<dyn std::error::Error>> {

    TerminalUI::clear_screen();

    let storage = Storage::new()?;
    let duress_engine = DuressEngine::new(&storage);

    // Initial Setup Phase
    if !storage.identity_exists() {
        println!("============================================================");
        println!(" HEXAPRIV P2P INITIAL SETUP - SET PASSCODES & IDENTITY     ");
        println!("============================================================");
        println!("Please create Code A (Real Code) and Code B (Duress Code).");
        println!("IMPORTANT: Code B will silently wipe all data if entered!\n");

        let code_a = TerminalUI::read_secure_input("Enter Code A (Real Passcode): ")?;
        let confirm_a = TerminalUI::read_secure_input("Confirm Code A: ")?;
        if code_a != confirm_a {
            println!("[!] Error: Code A passcodes do not match.");
            return Ok(());
        }

        let code_b = TerminalUI::read_secure_input("Enter Code B (Duress Silent Wipe Passcode): ")?;
        let confirm_b = TerminalUI::read_secure_input("Confirm Code B: ")?;
        if code_b != confirm_b {
            println!("[!] Error: Code B passcodes do not match.");
            return Ok(());
        }

        duress_engine.setup_passcodes(&code_a, &code_b)?;

        println!("\nGenerating Ed25519 & X25519 identity keypairs...");
        let (identity, _signing_key) = Identity::generate();
        let encrypted_file = identity.encrypt(&code_a)?;
        storage.save_identity(&encrypted_file)?;

        println!("\n[+] Setup Complete!");
        println!("[+] Public Key: {}", identity.public_key_hex);
        let fingerprint = compute_fingerprint(&identity.public_key_hex);
        println!("[+] Fingerprint: {}", fingerprint);
        TerminalUI::print_qr_code(&identity.public_key_hex);

        println!("Restart app to authenticate and launch Red & Black TUI dashboard.");
        return Ok(());
    }

    // Authentication Phase
    println!("============================================================");
    println!(" HEXAPRIV AUTHENTICATION REQUIRED                           ");
    println!("============================================================");
    let passcode = TerminalUI::read_secure_input("Enter Passcode: ")?;

    // Duress check (triggers silent wipe inside if duress code entered)
    duress_engine.authenticate(&passcode)?;

    let encrypted_file = storage.load_identity()?;
    let identity = Identity::decrypt(&encrypted_file, &passcode)?;
    let fingerprint = compute_fingerprint(&identity.public_key_hex);

    let p2p_port = override_port.unwrap_or(4001);
    let tor_proxy = env::var("TOR_PROXY_ADDR").ok();

    // Start P2P Network Service
    let p2p_service = P2pNetworkService::new(p2p_port, tor_proxy).await?;

    let app_state = Arc::new(Mutex::new(AppState::new(
        identity.public_key_hex.clone(),
        fingerprint,
    )));

    {
        let mut state = app_state.lock().await;
        state.tor_active = p2p_service.tor_connected;
        state.tor_proxy_addr = p2p_service.tor_proxy_addr.clone();
        state.p2p_listen_addr = format!("/ip4/0.0.0.0/tcp/{}", p2p_port);
    }

    let ratchets: Arc<Mutex<HashMap<String, RatchetState>>> = Arc::new(Mutex::new(HashMap::new()));
    let identity_arc = Arc::new(identity);

    // Spawn P2P Event processing listener for incoming events
    let event_rx = p2p_service.event_rx.clone();
    let app_state_event = app_state.clone();
    let ratchets_event = ratchets.clone();
    let identity_event = identity_arc.clone();

    tokio::spawn(async move {
        let mut rx = event_rx.lock().await;
        while let Some(evt) = rx.recv().await {
            let mut state = app_state_event.lock().await;
            match evt {
                P2pEvent::ListeningOn { multiaddr } => {
                    state.p2p_listen_addr = multiaddr.clone();
                    state.status_message = format!("Listening on {}", multiaddr);
                }
                P2pEvent::PeerConnected { peer_id } => {
                    state.connected_peers_count += 1;
                    state.peers.push(PeerItem {
                        pubkey_hex: peer_id.clone(),
                        fingerprint: compute_fingerprint(&peer_id),
                        multiaddr: "".to_string(),
                        is_online: true,
                    });
                    state.status_message = format!("Peer connected: {}", peer_id);
                }
                P2pEvent::PeerDisconnected { peer_id } => {
                    if state.connected_peers_count > 0 {
                        state.connected_peers_count -= 1;
                    }
                    state.peers.retain(|p| p.pubkey_hex != peer_id);
                    state.status_message = format!("Peer disconnected: {}", peer_id);
                }
                P2pEvent::MessageReceived { message } => {
                    let now = get_timestamp_string();
                    let conv_id = message.conversation_id.clone();
                    let sender_pub = message.sender_pubkey_hex.clone();

                    let ratchet_payload_res: Result<privacy_common::signal::EncryptedRatchetMessage, _> =
                        serde_json::from_str(&message.ratchet_payload_hex);

                    let decrypted_text = match ratchet_payload_res {
                        Ok(ratchet_msg) => {
                            let mut ratchets_guard = ratchets_event.lock().await;
                            let ratchet = ratchets_guard.entry(conv_id.clone()).or_insert_with(|| {
                                let seed = b"HexaprivDefaultSignalSeed123456";
                                RatchetState::init_bob(&conv_id, identity_event.secret_key_bytes, seed)
                            });

                            match ratchet.decrypt(&ratchet_msg) {
                                Ok(dec_bytes) => String::from_utf8_lossy(&dec_bytes).to_string(),
                                Err(e) => format!("[Decryption Error: {}]", e),
                            }
                        }
                        Err(_) => "[Invalid Payload Format]".to_string(),
                    };

                    state.messages.push(UiMessage {
                        timestamp: now,
                        sender: sender_pub[..8].to_string(),
                        text: decrypted_text,
                        is_self: false,
                        ratchet_info: Some("SIGNAL-E2EE".to_string()),
                    });
                }
                P2pEvent::TorStatus { connected, proxy_addr } => {
                    state.tor_active = connected;
                    state.tor_proxy_addr = proxy_addr;
                }
                P2pEvent::InfoLog { message } => {
                    state.status_message = message;
                }
                _ => {}
            }
        }
    });

    // Launch Red & Black TUI
    let p2p_cmd_tx = p2p_service.command_tx.clone();
    let app_state_cmd = app_state.clone();
    let ratchets_cmd = ratchets.clone();
    let identity_cmd = identity_arc.clone();
    let storage_cmd = Arc::new(storage);

    let mut tui_app = TerminalApp::new(app_state.clone())?;

    tui_app
        .run_loop(move |input: String| {
            let app_state_cmd = app_state_cmd.clone();
            let identity_cmd = identity_cmd.clone();
            let ratchets_cmd = ratchets_cmd.clone();
            let p2p_cmd_tx = p2p_cmd_tx.clone();
            let storage_cmd = storage_cmd.clone();

            async move {
                let parts: Vec<&str> = input.splitn(3, ' ').collect();
                let cmd = parts[0];


            match cmd {
                "/send" => {
                    if parts.len() < 3 {
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = "[!] Usage: /send <recipient_pubkey> <message>".to_string();
                        return false;
                    }
                    let recipient_pubkey = parts[1];
                    let msg_text = parts[2];

                    if recipient_pubkey.len() != 64 {
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = "[!] Recipient public key must be 64 hex characters".to_string();
                        return false;
                    }

                    // Derive conversation ID from sorted public keys
                    let mut keys = vec![identity_cmd.public_key_hex.as_str(), recipient_pubkey];
                    keys.sort();
                    let conv_id = hex::encode(&sha2::Sha256::digest(format!("{}:{}", keys[0], keys[1]).as_bytes()))[..16].to_string();

                    let recipient_dh_bytes = match hex::decode(recipient_pubkey) {
                        Ok(b) if b.len() == 32 => {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b);
                            arr
                        }
                        _ => {
                            let mut state = app_state_cmd.lock().await;
                            state.status_message = "[!] Invalid recipient key bytes".to_string();
                            return false;
                        }
                    };

                    let mut ratchets_guard = ratchets_cmd.lock().await;
                    let ratchet = ratchets_guard.entry(conv_id.clone()).or_insert_with(|| {
                        let seed = b"HexaprivDefaultSignalSeed123456";
                        RatchetState::init_alice(&conv_id, identity_cmd.secret_key_bytes, recipient_dh_bytes, seed)
                            .unwrap_or_else(|_| RatchetState::init_bob(&conv_id, identity_cmd.secret_key_bytes, seed))
                    });

                    match ratchet.encrypt(msg_text.as_bytes()) {
                        Ok(ratchet_msg) => {
                            let ratchet_json = serde_json::to_string(&ratchet_msg).unwrap();
                            let p2p_msg = DirectP2pMessage {
                                sender_pubkey_hex: identity_cmd.public_key_hex.clone(),
                                recipient_pubkey_hex: recipient_pubkey.to_string(),
                                conversation_id: conv_id.clone(),
                                ratchet_payload_hex: ratchet_json,
                                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                            };

                            let mut state = app_state_cmd.lock().await;
                            let target_peer = state.peers.iter().find(|p| p.pubkey_hex == recipient_pubkey).map(|p| p.pubkey_hex.clone());

                            if let Some(target_peer_str) = target_peer {
                                if let Ok(peer_id) = target_peer_str.parse::<libp2p::PeerId>() {
                                    let _ = p2p_cmd_tx.try_send(P2pCommand::SendMessage {
                                        target_peer_id: peer_id,
                                        message: p2p_msg,
                                    });
                                }
                            }

                            state.messages.push(UiMessage {
                                timestamp: get_timestamp_string(),
                                sender: "YOU".to_string(),
                                text: msg_text.to_string(),
                                is_self: true,
                                ratchet_info: Some(format!("SEQ #{}", ratchet_msg.header.n)),
                            });
                            state.status_message = format!("Signal Double Ratchet message encrypted & dispatched (Conv: {})", conv_id);

                            let _ = storage_cmd.save_message(&conv_id, &hex::encode(rand::random::<[u8; 4]>()), &format!("Me: {}", msg_text));
                        }
                        Err(e) => {
                            let mut state = app_state_cmd.lock().await;
                            state.status_message = format!("[!] Ratchet encryption error: {}", e);
                        }
                    }
                }
                "/connect" => {
                    if parts.len() < 2 {
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = "[!] Usage: /connect <multiaddr>".to_string();
                        return false;
                    }
                    let mut raw_addr = parts[1].to_string();
                    if !raw_addr.starts_with('/') && raw_addr.contains("onion") {
                        raw_addr = format!("/onion3/{}", raw_addr);
                    }
                    let sanitized = raw_addr.replace(".onion", "");
                    if let Ok(addr) = sanitized.parse::<Multiaddr>() {
                        let _ = p2p_cmd_tx.try_send(P2pCommand::DialPeer { addr: addr.clone() });
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = format!("Dialing multiaddress {}", addr);
                    } else if let Ok(addr) = parts[1].parse::<Multiaddr>() {
                        let _ = p2p_cmd_tx.try_send(P2pCommand::DialPeer { addr: addr.clone() });
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = format!("Dialing multiaddress {}", addr);
                    } else {
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = "[!] Invalid multiaddress format".to_string();
                    }
                }
                "/delete" => {
                    if parts.len() < 2 {
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = "[!] Usage: /delete <conversation_id>".to_string();
                        return false;
                    }
                    let conv_id = parts[1];
                    let _ = storage_cmd.delete_conversation_keys(conv_id);
                    let mut state = app_state_cmd.lock().await;
                    state.status_message = format!("Conversation {} keys and message history destroyed", conv_id);
                }
                "/wipe" => {
                    let storage = storage_cmd.clone();
                    let engine = DuressEngine::new(&storage);
                    let _ = engine.trigger_duress_wipe();
                    return true;
                }
                "/verify" => {
                    if parts.len() < 2 {
                        let mut state = app_state_cmd.lock().await;
                        state.status_message = "[!] Usage: /verify <fingerprint>".to_string();
                        return false;
                    }
                    let target_fp = parts[1];
                    let my_fp = compute_fingerprint(&identity_cmd.public_key_hex);
                    let match_str = if target_fp.to_lowercase() == my_fp.to_lowercase() {
                        "MATCH [IDENTICAL]"
                    } else {
                        "MISMATCH [WARNING]"
                    };
                    let mut state = app_state_cmd.lock().await;
                    state.status_message = format!("Verification Result: {}", match_str);
                }
                "/help" => {
                    let mut state = app_state_cmd.lock().await;
                    state.messages.push(UiMessage {
                        timestamp: get_timestamp_string(),
                        sender: "HELP".to_string(),
                        text: "COMMANDS: /send <pubkey> <msg> | /connect <multiaddr> | /delete <conv_id> | /wipe | /verify <fp> | /exit".to_string(),
                        is_self: false,
                        ratchet_info: None,
                    });
                }
                "/exit" => {
                    return true;
                }
                _ => {
                    let mut state = app_state_cmd.lock().await;
                    state.status_message = format!("[!] Unknown command: {}. Type /help", cmd);
                }
            }

                false
            }
        })
        .await?;



    Ok(())
}

fn get_timestamp_string() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let hours = (now / 3600) % 24;
    let mins = (now / 60) % 60;
    let secs = now % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}




