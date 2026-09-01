# HEXAPRIV // PRIVACY TEXT

> **Zero-Knowledge, Serverless P2P Terminal Messenger**  
> Powered by **Signal Protocol Double Ratchet E2EE**, **libp2p Swarm**, **Embedded Arti Tor Engine**, and a **Cyberpunk Red & Black Ratatui TUI**.

---

## Technical Highlights

- **Signal Protocol Double Ratchet E2EE**: Every message exchange executes an X25519 Diffie-Hellman ratchet and HKDF-SHA256 chain ratchet, guaranteeing **Forward Secrecy** and **Post-Compromise Security**.
- **Serverless libp2p Swarm**: Kademlia DHT peer discovery, Noise authenticated transport, and direct node-to-node CBOR messaging eliminate intermediate central servers.
- **Embedded Arti Tor Network (`arti-client`)**: Native Rust embedded Tor client bootstraps anonymized circuits directly within Hexapriv—hiding IP addresses and bypassing NAT firewalls without external proxy binaries. Enables **Global Anonymous Remote Communications**. See [TOR_COMMUNICATIONS_GUIDE.md](file:///home/johnny/Documents/Projects/Privacy%20Text/TOR_COMMUNICATIONS_GUIDE.md) for full details.
- **Red & Black Ratatui TUI**: Real-time terminal interface with dynamic network badges, peer sidebar, scrollable ratchet feed, and command prompt.
- **Duress System & Silent Forensic Wipe**: Dual passcode architecture (Code A vs. Code B). Entering Code B or triggering `/wipe` immediately overwrites local identity files with zeroes, renders decoy output, and exits.


---

## 1. System Requirements & Quick Installation

### Prerequisites
- **Operating System**: Linux, macOS, or BSD
- **Rust Toolchain**: `rustc` 1.75+ and `cargo` installed
- **C Build Tools**: `gcc`, `make`, and standard C runtime headers

### Automated Installation

Clone or enter the project directory and run the installer:

```bash
cd "/home/johnny/Documents/Projects/Privacy Text"
./install.sh
```

`install.sh` compiles the optimized release binary (`cargo build --release`) with bundled SQLite, installing `hexapriv` directly to `$HOME/.local/bin/hexapriv` and `$HOME/.cargo/bin/hexapriv`.

Verify installation:

```bash
hexapriv version
hexapriv help
```

---

## 2. CLI Command & Execution Modes

| Execution Command | Mode & Description |
|---|---|
| `hexapriv` | Launches pure P2P node on default port `4001` with Red & Black TUI dashboard. |
| `hexapriv p2p [PORT]` | Starts P2P node on a specified TCP port (e.g. `hexapriv p2p 5001`). |
| `hexapriv tor` | Starts P2P node with Tor network routing enabled via embedded Arti & SOCKS5. |
| `hexapriv connect [RELAY_URL]` | Connects to a fallback blind relay server (e.g. `http://127.0.0.1:8080`). |
| `hexapriv serve [PORT]` | Starts an optional zero-log blind relay server daemon (default port: `8080`). |
| `hexapriv verify <FINGERPRINT>` | Performs out-of-band SHA-256 identity fingerprint verification via CLI. |
| `hexapriv wipe` | Instantly triggers silent duress wipe from terminal command line. |
| `hexapriv version` | Displays version and enabled cryptographic features. |
| `hexapriv help` | Displays full CLI manual. |

---

## 3. Initial Setup & Authentication Flow

### First-Time Initialization
When launching `hexapriv` for the first time:

1. **Set Code A (Real Passcode)**: Unlocks your encrypted identity and opens normal messaging sessions.
2. **Set Code B (Duress Silent Wipe Passcode)**: **WARNING**: Entering Code B at login silently and permanently overwrites all local keys, databases, and message histories with zeroes before terminating the session.
3. **Key Generation**: Hexapriv automatically generates Ed25519 signing keys and X25519 Diffie-Hellman keypairs, storing them encrypted with Argon2id + ChaCha20-Poly1305 in `~/.secure-messenger/identity`.

### Subsequent Logins
Enter **Code A** to unlock the Red & Black TUI dashboard.

---

## 4. How to Connect Peers and Send Messages

### Connecting to a Remote Node
Nodes discover each other via Multiaddresses over libp2p or Kademlia DHT. To dial a peer directly:

```text
/connect /ip4/198.51.100.4/tcp/4001/p2p/12D3KooW...
```

Upon connection:
- The peer's `PeerId` appears in the **PEERS & SWARM** sidebar on the left with a glowing red indicator (`●`).
- Your node's exact multiaddresses (Direct P2P, Tor SOCKS/Arti, Tor `.onion` Hidden Service, Relay Fallback, and Fingerprints) are listed in the **CONNECTION TYPES & ADDRESSES** panel on the right side of the dashboard.
- The status bar updates to reflect connected peer counts.


### Sending Signal Double Ratchet E2EE Messages
To send an end-to-end encrypted message to a peer using their 64-character public key:

```text
/send <recipient_public_key_hex> <your message text here>
```

**Protocol Sequence on `/send`**:
1. If no session exists, Hexapriv executes an initial Diffie-Hellman agreement using the recipient's public key.
2. The message is encrypted using a unique per-message symmetric key ($MK$) derived from the symmetric ratchet.
3. The encrypted payload and Double Ratchet header (containing current sequence number $N$) are transmitted over the libp2p P2P swarm.
4. The message appears in your feed as `[YOU] [SEQ #0] your message text here`.
5. The recipient's node receives the payload, executes the receiving ratchet, decrypts the message, and displays it in their feed.

---

## 5. Interactive TUI Dashboard Commands

Inside the active Red & Black terminal dashboard:

| Interactive Command | Description |
|---|---|
| `/send <pubkey_hex> <msg>` | Encrypts message via Signal Double Ratchet E2EE and dispatches over libp2p. |
| `/connect <multiaddr>` | Dials target peer multiaddress (`/ip4/x.x.x.x/tcp/4001/p2p/12D3...`). |
| `/delete <conv_id>` | Permanently destroys local Double Ratchet session keys and conversation history. |
| `/verify <fingerprint>` | Performs out-of-band SHA-256 fingerprint comparison against local identity. |
| `/wipe` | Triggers manual instant duress silent wipe of all data. |
| `/help` | Displays quick interactive command reference overlay. |
| `/exit` | Restores terminal state cleanly and exits session. |
| `Ctrl + A` / `Esc` | Opens full un-clipped Network Connection Addresses modal window. |
| `Ctrl + Q` / `Esc` | Toggles the out-of-band Verification QR Code modal window. |
| `Ctrl + C` | Emergency exit application. |


---

## 6. Verification & Fingerprints

To protect against Man-in-the-Middle (MitM) attacks:

1. Press `Ctrl + Q` inside the TUI dashboard to view your public key QR code and SHA-256 fingerprint.
2. Share your fingerprint out-of-band (e.g. in person or via encrypted call).
3. Your peer executes `/verify <your_fingerprint>`.
4. If fingerprints match, the TUI displays `MATCH [IDENTICAL]` in neon red.

---

## 7. Security Architecture & Threat Model

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        HEXAPRIV NODE ARCHITECTURE                      │
├────────────────────────────────────────────────────────────────────────┤
│  [ TUI Layer ]          Red & Black Ratatui Cyber Dashboard           │
├────────────────────────────────────────────────────────────────────────┤
│  [ Crypto Engine ]      Signal Double Ratchet (X25519 + HKDF + ChaCha) │
├────────────────────────────────────────────────────────────────────────┤
│  [ Transport Layer ]    libp2p Swarm (Kademlia DHT + Noise + Yamux)    │
├────────────────────────────────────────────────────────────────────────┤
│  [ Anonymity Layer ]    Embedded Arti Tor Client (IP Address Concealment)│
├────────────────────────────────────────────────────────────────────────┤
│  [ Forensic Storage ]   Argon2id Key Derivation + Zeroize RAM Buffers │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Zero Central Dependencies**: Direct node-to-node communication over libp2p swarms means no central server has access to metadata, IP addresses, or message routing tables.
2. **Zeroize Memory Protection**: All secret keys, derived ratchet states, and plaintext message buffers implement `zeroize::ZeroizeOnDrop` to scrub memory when variables leave scope.
3. **IP Leak Prevention**: Address announcements strip internal LAN IP addresses (`192.168.x.x`, `10.x.x.x`) to prevent local network exposure over Tor peer discovery.
