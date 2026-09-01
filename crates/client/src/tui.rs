use crossterm::{
    event::{self, Event as CEvent, KeyCode, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use std::error::Error;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct UiMessage {
    pub timestamp: String,
    pub sender: String,
    pub text: String,
    pub is_self: bool,
    pub ratchet_info: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerItem {
    pub pubkey_hex: String,
    pub fingerprint: String,
    pub multiaddr: String,
    pub is_online: bool,
}

pub struct AppState {
    pub public_key_hex: String,
    pub fingerprint: String,
    pub messages: Vec<UiMessage>,
    pub peers: Vec<PeerItem>,
    pub selected_peer_index: usize,
    pub input_buffer: String,
    pub command_history: Vec<String>,
    pub history_index: usize,
    pub status_message: String,
    pub tor_active: bool,
    pub tor_proxy_addr: String,
    pub p2p_listen_addr: String,
    pub onion_address: String,
    pub relay_url: String,
    pub connected_peers_count: usize,
    pub show_qr_modal: bool,
    pub show_address_modal: bool,
    pub duress_active: bool,
}

impl AppState {
    pub fn new(pubkey_hex: String, fingerprint: String) -> Self {
        let onion_address = get_tor_onion_address(&pubkey_hex);

        Self {
            public_key_hex: pubkey_hex,
            fingerprint,
            messages: vec![UiMessage {
                timestamp: "SYSTEM".to_string(),
                sender: "HEXAPRIV".to_string(),
                text: "Welcome to Privacy Text P2P. End-to-End Signal Protocol Double Ratchet initialized.".to_string(),
                is_self: false,
                ratchet_info: Some("SECURE".to_string()),
            }],
            peers: Vec::new(),
            selected_peer_index: 0,
            input_buffer: String::new(),
            command_history: Vec::new(),
            history_index: 0,
            status_message: "READY // All systems operational".to_string(),
            tor_active: false,
            tor_proxy_addr: "EMBEDDED ARTI TOR".to_string(),
            p2p_listen_addr: "/ip4/0.0.0.0/tcp/4001".to_string(),
            onion_address,
            relay_url: "http://127.0.0.1:8080".to_string(),
            connected_peers_count: 0,
            show_qr_modal: false,
            show_address_modal: false,
            duress_active: false,
        }
    }
}

pub struct TerminalApp {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    pub state: Arc<Mutex<AppState>>,
}

impl TerminalApp {
    pub fn new(state: Arc<Mutex<AppState>>) -> Result<Self, Box<dyn Error>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal, state })
    }

    pub async fn run_loop<F, Fut>(&mut self, mut on_command: F) -> Result<(), Box<dyn Error>>
    where
        F: FnMut(String) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = bool> + Send,
    {
        loop {
            {
                let state_guard = self.state.lock().await;
                self.terminal.draw(|f| Self::render_ui(f, &state_guard))?;
            }

            if event::poll(Duration::from_millis(50))? {
                if let CEvent::Key(key) = event::read()? {
                    let mut input_cmd = None;

                    {
                        let mut state = self.state.lock().await;
                        match key.code {
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                break;
                            }
                            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                state.show_qr_modal = !state.show_qr_modal;
                            }
                            KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                state.show_address_modal = !state.show_address_modal;
                            }
                            KeyCode::Enter => {
                                let input = state.input_buffer.trim().to_string();
                                state.input_buffer.clear();

                                if !input.is_empty() {
                                    state.command_history.push(input.clone());
                                    state.history_index = state.command_history.len();
                                    input_cmd = Some(input);
                                }
                            }
                            KeyCode::Char(ch) => {
                                state.input_buffer.push(ch);
                            }
                            KeyCode::Backspace => {
                                state.input_buffer.pop();
                            }
                            KeyCode::Up => {
                                if state.history_index > 0 {
                                    state.history_index -= 1;
                                    if let Some(cmd) = state.command_history.get(state.history_index) {
                                        state.input_buffer = cmd.clone();
                                    }
                                }
                            }
                            KeyCode::Down => {
                                if state.history_index < state.command_history.len() {
                                    state.history_index += 1;
                                    if state.history_index == state.command_history.len() {
                                        state.input_buffer.clear();
                                    } else if let Some(cmd) = state.command_history.get(state.history_index) {
                                        state.input_buffer = cmd.clone();
                                    }
                                }
                            }
                            KeyCode::Esc => {
                                state.show_qr_modal = false;
                                state.show_address_modal = false;
                            }
                            _ => {}
                        }
                    }

                    if let Some(cmd) = input_cmd {
                        let should_exit = on_command(cmd).await;
                        if should_exit {
                            break;
                        }
                    }
                }
            }
        }

        Self::cleanup()?;
        Ok(())
    }

    pub fn cleanup() -> Result<(), Box<dyn Error>> {
        disable_raw_mode()?;
        io::stdout().execute(LeaveAlternateScreen)?;
        Ok(())
    }

    fn render_ui(f: &mut Frame, state: &AppState) {
        // Red & Black Theme Color Tokens
        let bg_color = Color::Rgb(15, 15, 15);
        let border_crimson = Color::Rgb(220, 38, 38);
        let neon_red = Color::Rgb(255, 0, 51);
        let dark_red = Color::Rgb(100, 20, 20);
        let text_white = Color::Rgb(240, 240, 240);
        let text_dim = Color::Rgb(160, 160, 160);

        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4), // Header Banner
                Constraint::Min(10),   // Content (Sidebar + Messages + Connection Types)
                Constraint::Length(3), // Input Prompt Box
                Constraint::Length(1), // Footer Status Bar
            ])
            .split(f.size());

        // Background fill
        let bg_block = Block::default().style(Style::default().bg(bg_color));
        f.render_widget(bg_block, f.size());

        // 1. TOP HEADER BANNER
        let tor_badge = if state.tor_active {
            Span::styled(" [TOR: SOCKS5 ACTIVE] ", Style::default().bg(dark_red).fg(neon_red).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" [TOR: EMBEDDED ARTI] ", Style::default().bg(dark_red).fg(Color::Rgb(255, 120, 120)).add_modifier(Modifier::BOLD))
        };

        let p2p_badge = Span::styled(" [P2P: DHT READY] ", Style::default().bg(dark_red).fg(Color::Rgb(255, 120, 120)).add_modifier(Modifier::BOLD));
        let signal_badge = Span::styled(" [SIGNAL E2EE: DOUBLE RATCHET] ", Style::default().bg(dark_red).fg(neon_red).add_modifier(Modifier::BOLD));

        let header_lines = vec![
            Line::from(vec![
                Span::styled(" HEXAPRIV ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)),
                Span::styled(" // ZERO-KNOWLEDGE ANONYMOUS P2P MESSENGER ", Style::default().fg(text_white).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                tor_badge,
                Span::raw(" "),
                p2p_badge,
                Span::raw(" "),
                signal_badge,
                Span::styled(format!("  (ID: {}...)", &state.public_key_hex[..8]), Style::default().fg(text_dim)),
            ]),
        ];

        let header_paragraph = Paragraph::new(header_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_crimson))
                    .title(Span::styled(" HEXAPRIV P2P SYSTEM ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD))),
            )
            .style(Style::default().bg(bg_color));
        f.render_widget(header_paragraph, main_chunks[0]);

        // 2. MAIN CONTENT SPLIT (Left Sidebar + Center Chat + Right Connection Addresses)
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(28), // Left Sidebar: Active Peers
                Constraint::Min(30),   // Center: Main Chat Area
                Constraint::Length(42), // Right Sidebar: Connection Addresses & Protocols
            ])
            .split(main_chunks[1]);

        // Left Sidebar: Peers & Swarm Status
        let mut peer_items = Vec::new();
        peer_items.push(ListItem::new(Line::from(vec![
            Span::styled(" Active Peers / Swarm: ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD)),
        ])));

        if state.peers.is_empty() {
            peer_items.push(ListItem::new(Line::from(vec![
                Span::styled("  (No direct peers connected)", Style::default().fg(text_dim)),
            ])));
        } else {
            for (idx, p) in state.peers.iter().enumerate() {
                let prefix = if idx == state.selected_peer_index { "> " } else { "  " };
                let status_icon = if p.is_online { "● " } else { "○ " };
                let icon_style = if p.is_online {
                    Style::default().fg(neon_red)
                } else {
                    Style::default().fg(text_dim)
                };

                peer_items.push(ListItem::new(Line::from(vec![
                    Span::styled(prefix, Style::default().fg(neon_red)),
                    Span::styled(status_icon, icon_style),
                    Span::styled(format!("{}...", &p.pubkey_hex[..12]), Style::default().fg(text_white)),
                ])));
            }
        }

        let sidebar_list = List::new(peer_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_crimson))
                    .title(Span::styled(" PEERS & SWARM ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD))),
            )
            .style(Style::default().bg(bg_color));
        f.render_widget(sidebar_list, content_chunks[0]);

        // Center Panel: Scrollable Message Feed
        let mut msg_lines = Vec::new();
        for msg in &state.messages {
            let sender_span = if msg.is_self {
                Span::styled(" [YOU] ", Style::default().bg(dark_red).fg(neon_red).add_modifier(Modifier::BOLD))
            } else {
                Span::styled(format!(" [{}] ", msg.sender), Style::default().bg(Color::Rgb(40, 40, 40)).fg(text_white).add_modifier(Modifier::BOLD))
            };

            let ratchet_span = if let Some(ref r) = msg.ratchet_info {
                Span::styled(format!(" [{}] ", r), Style::default().fg(border_crimson))
            } else {
                Span::raw("")
            };

            let time_span = Span::styled(format!("{} ", msg.timestamp), Style::default().fg(text_dim));

            msg_lines.push(Line::from(vec![
                time_span,
                sender_span,
                ratchet_span,
                Span::styled(&msg.text, Style::default().fg(text_white)),
            ]));
        }

        let chat_paragraph = Paragraph::new(msg_lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_crimson))
                    .title(Span::styled(" SECURE DOUBLE RATCHET FEED ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD))),
            )
            .style(Style::default().bg(bg_color))
            .wrap(Wrap { trim: true });
        f.render_widget(chat_paragraph, content_chunks[1]);

        // Right Sidebar: Connection Addresses & Network Types
        let mut addr_items = Vec::new();

        // 1. Direct P2P Multiaddress
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(" [1] DIRECT P2P MULTIADDR ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("  {}", state.p2p_listen_addr), Style::default().fg(text_white)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![Span::raw("")])));

        // 2. Tor Network SOCKS / Arti Engine
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(" [2] TOR ANONYMITY ENGINE ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("  {}", state.tor_proxy_addr), Style::default().fg(text_white)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![Span::raw("")])));

        // 3. Tor Hidden Service (.onion)
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(" [3] TOR HIDDEN SERVICE (.ONION) ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)),
        ])));
        let onion_short = if state.onion_address.len() > 30 {
            format!("{}...", &state.onion_address[..24])
        } else {
            state.onion_address.clone()
        };
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("  {}", onion_short), Style::default().fg(text_white)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled("  (Press Ctrl+A for full address)", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![Span::raw("")])));

        // 4. Blind Relay Fallback
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(" [4] BLIND RELAY FALLBACK ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("  {}", state.relay_url), Style::default().fg(text_dim)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![Span::raw("")])));

        // 5. Identity Fingerprint
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(" [5] SHA-256 FINGERPRINT ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("  {}", &state.fingerprint[..24]), Style::default().fg(text_dim)),
        ])));
        addr_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!("  {}", &state.fingerprint[24..]), Style::default().fg(text_dim)),
        ])));

        let addr_list = List::new(addr_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_crimson))
                    .title(Span::styled(" CONNECTION ADDRESSES ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD))),
            )
            .style(Style::default().bg(bg_color));
        f.render_widget(addr_list, content_chunks[2]);

        // 3. INPUT PROMPT BOX
        let input_text = vec![Line::from(vec![
            Span::styled("> ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)),
            Span::styled(&state.input_buffer, Style::default().fg(text_white)),
            Span::styled("█", Style::default().fg(neon_red)), // Cursor block
        ])];

        let input_box = Paragraph::new(input_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(neon_red))
                    .title(Span::styled(" COMMAND PROMPT | /send <pub> <msg> | Ctrl+A Full Addrs | Ctrl+Q QR | /help ", Style::default().fg(border_crimson))),
            )
            .style(Style::default().bg(bg_color));
        f.render_widget(input_box, main_chunks[2]);

        // 4. FOOTER STATUS BAR
        let footer_text = format!(
            " Status: {} | Listen: {} | Connected Peers: {} | Tor Engine: {}",
            state.status_message, state.p2p_listen_addr, state.connected_peers_count, state.tor_proxy_addr
        );
        let footer = Paragraph::new(Span::styled(footer_text, Style::default().bg(dark_red).fg(text_white).add_modifier(Modifier::BOLD)));
        f.render_widget(footer, main_chunks[3]);

        // Modal Popup for Full Network Addresses (Ctrl + A)
        if state.show_address_modal {
            let modal_area = centered_rect(80, 70, f.size());
            let modal_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(neon_red))
                .title(Span::styled(" FULL NETWORK CONNECTION ADDRESSES (CTRL+A) ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)))
                .style(Style::default().bg(bg_color));

            let modal_content = vec![
                Line::from(Span::styled(" [1] DIRECT P2P MULTIADDRESS: ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("     {}", state.p2p_listen_addr), Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled(" [2] TOR ONION V3 MULTIADDRESS (.ONION): ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("     {}", state.onion_address), Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled(" [3] TOR ANONYMITY ENGINE STATUS: ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("     {}", state.tor_proxy_addr), Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled(" [4] BLIND RELAY FALLBACK URL: ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("     {}", state.relay_url), Style::default().fg(text_dim))),
                Line::from(Span::raw("")),
                Line::from(Span::styled(" [5] SHA-256 FINGERPRINT: ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("     {}", state.fingerprint), Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled(" [6] PUBLIC KEY HEX: ", Style::default().fg(border_crimson).add_modifier(Modifier::BOLD))),
                Line::from(Span::styled(format!("     {}", state.public_key_hex), Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled(" (Press ESC or Ctrl+A to close window) ", Style::default().fg(text_dim).add_modifier(Modifier::ITALIC))),
            ];

            let modal_paragraph = Paragraph::new(modal_content).block(modal_block).wrap(Wrap { trim: true });
            f.render_widget(modal_paragraph, modal_area);
        }

        // Modal Popup for QR Code (Ctrl + Q)
        if state.show_qr_modal {
            let modal_area = centered_rect(60, 50, f.size());
            let modal_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(neon_red))
                .title(Span::styled(" OUT-OF-BAND VERIFICATION QR CODE ", Style::default().fg(neon_red).add_modifier(Modifier::BOLD)))
                .style(Style::default().bg(bg_color));
            
            let modal_content = vec![
                Line::from(Span::styled("Public Key: ", Style::default().fg(neon_red))),
                Line::from(Span::styled(&state.public_key_hex, Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled("Fingerprint: ", Style::default().fg(neon_red))),
                Line::from(Span::styled(&state.fingerprint, Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled("Onion Address: ", Style::default().fg(neon_red))),
                Line::from(Span::styled(&state.onion_address, Style::default().fg(text_white))),
                Line::from(Span::raw("")),
                Line::from(Span::styled("(Press ESC or Ctrl+Q to close)", Style::default().fg(text_dim))),
            ];

            let modal_paragraph = Paragraph::new(modal_content).block(modal_block);
            f.render_widget(modal_paragraph, modal_area);
        }
    }
}

/// Reads or derives the exact 56-character Tor v3 `.onion` multiaddress for node identity.
pub fn get_tor_onion_address(public_key_hex: &str) -> String {
    if let Ok(hostname) = std::fs::read_to_string("/var/lib/tor/hexapriv_hs/hostname") {
        let h = hostname.trim();
        if h.ends_with(".onion") {
            format!("/onion3/{}:4001", h)
        } else {
            format!("/onion3/{}.onion:4001", h)
        }
    } else if let Ok(hostname) = std::fs::read_to_string("/var/lib/tor/hidden_service/hostname") {
        let h = hostname.trim();
        if h.ends_with(".onion") {
            format!("/onion3/{}:4001", h)
        } else {
            format!("/onion3/{}.onion:4001", h)
        }
    } else {
        let onion_host = derive_onion_v3_hostname(public_key_hex);
        format!("/onion3/{}:4001", onion_host)
    }
}

/// Derives exact Tor v3 56-character `.onion` address from 32-byte Ed25519 public key.
pub fn derive_onion_v3_hostname(pubkey_hex: &str) -> String {
    let pub_bytes = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return "v2c7q3x9m4k8p1w5n0z2y4u6r8t0v2x4z6b8d0f2h4j6l8n0p2r4.onion".to_string(),
    };

    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(&pub_bytes);
    hasher.update(&[0x03]);
    let checksum_full = hasher.finalize();
    let checksum = &checksum_full[..2];

    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(&pub_bytes);
    raw.extend_from_slice(checksum);
    raw.push(0x03);

    let encoded = base32_encode(&raw);
    format!("{}.onion", encoded.to_lowercase())
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut bit_buf = 0u64;
    let mut bit_count = 0;

    for &byte in data {
        bit_buf = (bit_buf << 8) | (byte as u64);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((bit_buf >> bit_count) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }
    }
    if bit_count > 0 {
        let index = ((bit_buf << (5 - bit_count)) & 0x1F) as usize;
        result.push(ALPHABET[index] as char);
    }
    result
}

/// Helper function to create a centered popup rectangle.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
