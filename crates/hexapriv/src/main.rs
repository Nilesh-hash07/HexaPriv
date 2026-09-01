use privacy_client::duress::DuressEngine;
use privacy_client::storage::Storage;
use privacy_common::protocol::compute_fingerprint;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        // Default execution: launch client P2P node with Red & Black TUI
        return privacy_client::run_client(None, None).await;
    }

    let first_arg = args[1].as_str();
    match first_arg {
        "p2p" | "--p2p" | "start" => {
            let port: u16 = if args.len() > 2 {
                args[2].parse().unwrap_or(4001)
            } else {
                4001
            };
            privacy_client::run_client(None, Some(port)).await?;
        }

        "tor" | "tor-start" | "--tor" => {
            println!("[+] Enabling Tor network SOCKS5 proxy routing (127.0.0.1:9050)...");
            env::set_var("TOR_PROXY_ADDR", "127.0.0.1:9050");
            privacy_client::run_client(None, None).await?;
        }

        "connect" | "--connect" | "-c" => {
            let url = if args.len() > 2 {
                Some(args[2].clone())
            } else {
                None
            };
            privacy_client::run_client(url, None).await?;
        }

        "serve" | "--serve" | "-s" => {
            let port: u16 = if args.len() > 2 {
                args[2].parse().unwrap_or(8080)
            } else {
                8080
            };
            privacy_relay::run_relay(port).await?;
        }

        "verify" | "--verify" => {
            if args.len() < 3 {
                println!("[!] Usage: hexapriv --verify <fingerprint>");
                return Ok(());
            }
            let target_fp = &args[2];
            let storage = Storage::new()?;
            if !storage.identity_exists() {
                println!("[!] Error: Identity does not exist. Run hexapriv first to create identity.");
                return Ok(());
            }
            let enc_file = storage.load_identity()?;
            let my_fp = compute_fingerprint(&enc_file.public_key_hex);

            println!("\n--- Hexapriv Fingerprint Verification ---");
            println!(" Your Public Key:   {}", enc_file.public_key_hex);
            println!(" Your Fingerprint:   {}", my_fp);
            println!(" Target Fingerprint: {}", target_fp);
            if target_fp.to_lowercase() == my_fp.to_lowercase() {
                println!(" Result: [MATCH] Fingerprints are identical.");
            } else {
                println!(" Result: [MISMATCH] Fingerprints do NOT match!");
            }
            println!("------------------------------------------\n");
        }

        "wipe" | "--wipe" => {
            println!("[!] Triggering instant silent duress wipe via Hexapriv CLI...");
            let storage = Storage::new()?;
            let engine = DuressEngine::new(&storage);
            engine.trigger_duress_wipe()?;
        }

        "version" | "--version" | "-v" => {
            println!("hexapriv version 0.1.0 (Signal Protocol + libp2p + Tor)");
        }

        "help" | "--help" | "-h" => {
            print_usage();
        }

        _ => {
            println!("[!] Unknown option or command: {}", first_arg);
            print_usage();
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Hexapriv - Zero-Knowledge P2P Terminal Messenger v0.1.0");
    println!("Usage:");
    println!("  hexapriv                             Launch P2P node with Red & Black TUI");
    println!("  hexapriv p2p [PORT]                  Start P2P node on specific TCP port (default 4001)");
    println!("  hexapriv tor                         Start P2P node using Tor SOCKS5 network routing");
    println!("  hexapriv connect [RELAY_URL]         Connect client to fallback relay server");
    println!("  hexapriv serve [PORT]                Start the zero-log blind relay server (default 8080)");
    println!("  hexapriv verify <FINGERPRINT>        Out-of-band identity fingerprint verification");
    println!("  hexapriv wipe                        Instantly trigger silent duress wipe");
    println!("  hexapriv help                        Show this help manual");
    println!("  hexapriv version                     Show package version info");
}
