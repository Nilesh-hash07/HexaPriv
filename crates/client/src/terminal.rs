use privacy_common::protocol::{compute_fingerprint, sanitize_ascii};
use std::io::{self, Write};

pub struct TerminalUI;

impl TerminalUI {
    /// Clears stdout and scrollback buffer completely.
    pub fn clear_screen() {
        print!("\x1B[2J\x1B[3J\x1B[H");
        let _ = io::stdout().flush();
    }

    /// Reads password or passcode securely from stdin without echo.
    pub fn read_secure_input(prompt: &str) -> Result<String, String> {
        print!("{}", prompt);
        let _ = io::stdout().flush();
        let pass = rpassword::read_password()
            .map_err(|e| format!("Input read error: {}", e))?;
        Ok(sanitize_ascii(&pass))
    }

    /// Reads line input from stdin and sanitizes to ASCII.
    pub fn read_line_input(prompt: &str) -> Result<String, String> {
        print!("{}", prompt);
        let _ = io::stdout().flush();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Stdin read error: {}", e))?;
        Ok(sanitize_ascii(input.trim()))
    }

    /// Displays application header bar.
    pub fn print_header(public_key: &str) {
        let fingerprint = compute_fingerprint(public_key);
        println!("==================================================================");
        println!(" PRIVACY TEXT - ZERO-KNOWLEDGE TERMINAL MESSENGER                ");
        println!(" Public Key:  {}", public_key);
        println!(" Fingerprint: {}", fingerprint);
        println!("==================================================================");
    }

    /// Displays command help menu.
    pub fn print_help() {
        println!("\nCOMMANDS:");
        println!("  /send <recipient_public_key> <message>  Send encrypted message");
        println!("  /delete <conversation_id>              Destroy conversation keys & signals");
        println!("  /wipe                                  Manually trigger instant duress wipe");
        println!("  /verify <fingerprint>                  Out-of-band key fingerprint check");
        println!("  /list                                  List active conversations & messages");
        println!("  /help                                  Show this help menu");
        println!("  /exit                                  Clear screen and terminate session\n");
    }

    /// Renders QR code for public key to terminal for easy out-of-band sharing.
    pub fn print_qr_code(public_key: &str) {
        println!("\n--- Public Key QR Code (Out-of-band Verification) ---");
        if qr2term::print_qr(public_key).is_err() {
            println!("[!] Error rendering QR code on terminal display.");
        }
        println!("------------------------------------------------------\n");
    }
}
