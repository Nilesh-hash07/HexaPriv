# Hexapriv Tor Mode - Global Anonymous Communications Guide

This document details how **remote global communication** works in Hexapriv and provides a complete guide on utilizing **Tor Mode (`hexapriv tor`)** for 100% anonymous, serverless communications across the globe.

---

## Is Remote Global Communication Possible?

**YES! Absolutely.** Hexapriv is engineered specifically for global communication without geographic or network restrictions.

### Why Global Comms Work Out-of-the-Box:
1. **Tor Onion Routing (NAT Traversal)**: Devices behind home routers, mobile CGNAT (4G/5G), or restrictive national firewalls do not require port forwarding or public IP addresses. Tor automatically creates encrypted onion circuits between any two nodes worldwide.
2. **libp2p Kademlia DHT**: The distributed hash table locates peers globally using their cryptographic Ed25519 identity hashes.
3. **Signal Protocol Double Ratchet E2EE**: End-to-end encryption guarantees that even if internet service providers or network surveillance intercept packets across international undersea cables, message content remains mathematically unbreakable.

---

## How Tor Mode Works in Hexapriv

Hexapriv features a **dual-layer Tor integration**:

1. **Embedded Arti Tor Engine (`arti-client 0.45`)**: Hexapriv natively embeds the Official Tor Project's Rust client (`arti-client`). When launched, Hexapriv bootstraps its own internal Tor client—downloading consensus documents and creating circuits directly in memory without requiring external Tor software.
2. **SOCKS5 System Tor Interop**: If you already run a local Tor daemon (e.g. `tor` service on `127.0.0.1:9050`), Hexapriv automatically detects it and routes SOCKS5 traffic through your local daemon.

---

## Step-by-Step Guide: Launching & Using Tor Mode

### Step 1: Launch Hexapriv in Tor Mode

From any terminal window on your system, launch:

```bash
hexapriv tor
```

*Alternative*: Specify a custom Tor SOCKS5 proxy via environment variable:

```bash
TOR_PROXY_ADDR="127.0.0.1:9050" hexapriv
```

---

### Step 2: Verify Tor Anonymity Status in TUI

When the Red & Black Cyber Dashboard opens, inspect the top header banner:

- `[TOR: EMBEDDED ARTI (NATIVE TOR)]`: Indicates native embedded Rust Tor engine has bootstrapped and is actively anonymizing traffic.
- `[TOR: SOCKS5 ACTIVE]`: Indicates Hexapriv is routing all outbound/inbound P2P traffic through your local Tor SOCKS5 daemon (`127.0.0.1:9050`).

---

### Step 3: Global Peer Dialing over Tor

To connect with a remote peer located anywhere in the world:

1. Obtain your peer's **libp2p Multiaddress** or **Tor `.onion` address**:
   - Standard IPv4/IPv6 over Tor: `/ip4/198.51.100.4/tcp/4001/p2p/12D3KooW...`
   - Domain Name over Tor: `/dns4/peer.example.org/tcp/4001/p2p/12D3KooW...`
   - Tor Hidden Service: `/onion3/v2c7...onion:4001/p2p/12D3KooW...`

2. Inside the TUI command prompt, dial the peer:

```text
/connect /ip4/198.51.100.4/tcp/4001/p2p/12D3KooW...
```

3. When connected, the peer's `PeerId` turns glowing red (`●`) in your **PEERS & SWARM** sidebar.

---

### Step 4: Transmitting E2EE Messages Globally

Send end-to-end encrypted messages to your remote peer using their 64-character public key:

```text
/send 8a7c4f1e9b2... <your global message>
```

**What Happens Behind the Scenes**:
- Your node encrypts the plaintext using the **Signal Double Ratchet** per-message key ($MK$).
- The ciphertext is fragmented into anonymized Tor cells, routed through 3 random Tor relay nodes across the globe (Guard Node $\to$ Middle Node $\to$ Exit/Onion Node).
- Neither your ISP, your peer's ISP, nor intermediate Tor nodes can see your IP address, your peer's IP address, or the content of your conversation.

---

## Advanced Tor Features & Privacy Guarantees

| Security Layer | Threat Protected Against | Guarantee Provided |
|---|---|---|
| **Tor 3-Hop Circuits** | IP Tracking & Geo-location | Both Sender & Recipient IP addresses hidden |
| **Arti Native Embedding** | Dependency Hijacking | Zero external software binaries required |
| **Multiaddress Sanitization** | LAN Metadata Leaks | Local IPs (`192.168.x.x`) stripped before broadcast |
| **Signal Double Ratchet** | Passive Cable Tapping & MitM | Forward secrecy + post-compromise security |
| **Duress Silent Wipe** | Physical Device Seizure | Code B / `/wipe` zeroizes local databases in RAM/Disk |

---

## How to Find Your Tor Hidden Service (`.onion` Address)

There are two primary ways your node is identified on the network:

### Method 1: Via Hexapriv TUI Dashboard (Default)

1. Launch `hexapriv` or `hexapriv tor`.
2. Inside the TUI dashboard, press **`Ctrl + Q`** or view your **Fingerprint** in the left sidebar.
3. Your node's P2P address format is:
   ```text
   /ip4/<YOUR_TOR_EXIT_OR_PUBLIC_IP>/tcp/4001/p2p/<YOUR_PEER_ID>
   ```
   Or when using Tor hidden services:
   ```text
   /onion3/<YOUR_ONION_ADDRESS>:4001/p2p/<YOUR_PEER_ID>
   ```

---

### Method 2: Via Local Tor Daemon (System Tor Service)

If you are running the system Tor service (`sudo apt install tor`) on Linux/macOS and forwarding Hexapriv through a Tor Hidden Service:

1. Edit your system Tor configuration file (`/etc/tor/torrc`):
   ```text
   HiddenServiceDir /var/lib/tor/hexapriv_hs/
   HiddenServicePort 4001 127.0.0.1:4001
   ```

2. Restart Tor:
   ```bash
   sudo systemctl restart tor
   ```

3. Read your automatically generated `.onion` hostname:
   ```bash
   sudo cat /var/lib/tor/hexapriv_hs/hostname
   ```

   *Output Example*:
   ```text
   v2c7q3x9m4...xyz.onion
   ```

4. Share your Multiaddress with your remote peer:
   ```text
   /onion3/v2c7q3x9m4...xyz.onion:4001/p2p/<YOUR_PEER_ID>
   ```

---

## Troubleshooting Global Tor Connections

1. **Tor Bootstrapping Delay**: On initial launch, embedded Arti fetches directory consensus documents. This can take 5–15 seconds depending on your connection. The TUI status bar will show `[TOR: BOOTSTRAPPING ARTI...]` until consensus is reached.
2. **High Latency / Ping**: Tor routes traffic through 3 global relay hops for anonymity. A 200–800ms latency is normal for global Tor circuits.
3. **Strict Corporate Firewalls**: If outbound Tor ports (`9001/9050/443`) are blocked by an restrictive ISP, run `hexapriv connect http://relay.hexapriv.org` as a fallback.

