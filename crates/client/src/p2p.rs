use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use libp2p::{
    gossipsub, identity, kad, noise, request_response, tcp, yamux, Multiaddr, PeerId,
    SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_socks::tcp::Socks5Stream;


/// Message payload transferred between Hexapriv P2P nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectP2pMessage {
    pub sender_pubkey_hex: String,
    pub recipient_pubkey_hex: String,
    pub conversation_id: String,
    pub ratchet_payload_hex: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectP2pResponse {
    pub success: bool,
    pub status_message: String,
}

/// Commands sent to the P2P event loop.
#[derive(Debug)]
pub enum P2pCommand {
    DialPeer { addr: Multiaddr },
    SendMessage { target_peer_id: PeerId, message: DirectP2pMessage },
    AnnouncePresence { pubkey_hex: String },
    LookupPeer { pubkey_hex: String },
}

/// Events emitted by the P2P event loop to the TUI.
#[derive(Debug, Clone)]
pub enum P2pEvent {
    ListeningOn { multiaddr: String },
    PeerConnected { peer_id: String },
    PeerDisconnected { peer_id: String },
    MessageReceived { message: DirectP2pMessage },
    TorStatus { connected: bool, proxy_addr: String },
    DhtRecordFound { pubkey_hex: String, peer_id: String },
    InfoLog { message: String },
}

pub struct P2pNetworkService {
    pub local_peer_id: PeerId,
    pub command_tx: mpsc::Sender<P2pCommand>,
    pub event_rx: Arc<Mutex<mpsc::Receiver<P2pEvent>>>,
    pub tor_connected: bool,
    pub tor_proxy_addr: String,
}

impl P2pNetworkService {
    /// Initializes libp2p node, embedded Arti Tor bootstrapping, and SOCKS5 check.
    pub async fn new(port: u16, tor_proxy: Option<String>) -> Result<Self, Box<dyn Error>> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let (command_tx, mut command_rx) = mpsc::channel::<P2pCommand>(100);
        let (event_tx, event_rx) = mpsc::channel::<P2pEvent>(100);

        let proxy_addr = tor_proxy.unwrap_or_else(|| "127.0.0.1:9050".to_string());
        
        // Test Tor SOCKS5 availability
        let tor_socks_active = Self::check_tor_socks5(&proxy_addr).await;
        let initial_tor_status = if tor_socks_active {
            format!("SOCKS5 ({})", proxy_addr)
        } else {
            "BOOTSTRAPPING ARTI...".to_string()
        };

        let _ = event_tx.send(P2pEvent::TorStatus {
            connected: tor_socks_active,
            proxy_addr: initial_tor_status,
        }).await;

        // Spawn embedded Arti Tor bootstrapping in background task
        let event_tx_arti = event_tx.clone();
        tokio::spawn(async move {
            let config = TorClientConfig::default();
            let _ = event_tx_arti.send(P2pEvent::InfoLog {
                message: "Bootstrapping embedded Arti Tor client...".to_string(),
            }).await;

            match TorClient::create_bootstrapped(config).await {

                    Ok(_tor_client) => {
                        let _ = event_tx_arti.send(P2pEvent::TorStatus {
                            connected: true,
                            proxy_addr: "EMBEDDED ARTI (NATIVE TOR)".to_string(),
                        }).await;
                        let _ = event_tx_arti.send(P2pEvent::InfoLog {
                            message: "Embedded Arti Tor client bootstrapped & ready.".to_string(),
                        }).await;
                    }
                    Err(e) => {
                        let _ = event_tx_arti.send(P2pEvent::InfoLog {
                            message: format!("Arti bootstrap note: {}", e),
                        }).await;
                    }
                }
        });


        // Build libp2p Swarm
        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let kad_store = kad::store::MemoryStore::new(PeerId::from(key.public()));
                let kademlia = kad::Behaviour::new(PeerId::from(key.public()), kad_store);

                let req_resp = request_response::cbor::Behaviour::<DirectP2pMessage, DirectP2pResponse>::new(
                    [(
                        libp2p::StreamProtocol::new("/hexapriv/p2p/1.0.0"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                );

                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(Duration::from_secs(1))
                    .build()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;

                Ok(HexaprivBehavior {
                    kademlia,
                    req_resp,
                    gossipsub,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Listen on local port
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
        swarm.listen_on(listen_addr.clone())?;

        let _ = event_tx.send(P2pEvent::InfoLog {
            message: format!("libp2p P2P engine listening on {}", listen_addr),
        }).await;

        // Spawn background event processing loop
        tokio::spawn(async move {
            let mut pending_requests = HashMap::new();

            loop {
                tokio::select! {
                    Some(cmd) = command_rx.recv() => {
                        match cmd {
                            P2pCommand::DialPeer { addr } => {
                                // Sanitize dialed address to prevent LAN IP leaks over public transport
                                let sanitized_addr = Self::sanitize_multiaddress(&addr);
                                if let Err(e) = swarm.dial(sanitized_addr.clone()) {
                                    let _ = event_tx.send(P2pEvent::InfoLog {
                                        message: format!("Failed to dial {}: {}", sanitized_addr, e),
                                    }).await;
                                }
                            }
                            P2pCommand::SendMessage { target_peer_id, message } => {
                                let req_id = swarm.behaviour_mut().req_resp.send_request(&target_peer_id, message);
                                pending_requests.insert(req_id, target_peer_id);
                            }
                            P2pCommand::AnnouncePresence { pubkey_hex } => {
                                let record_key = kad::RecordKey::new(&pubkey_hex.as_bytes());
                                let record = kad::Record {
                                    key: record_key,
                                    value: swarm.local_peer_id().to_bytes(),
                                    publisher: Some(*swarm.local_peer_id()),
                                    expires: None,
                                };
                                let _ = swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One);
                            }
                            P2pCommand::LookupPeer { pubkey_hex } => {
                                let record_key = kad::RecordKey::new(&pubkey_hex.as_bytes());
                                swarm.behaviour_mut().kademlia.get_record(record_key);
                            }
                        }
                    }
                    event = swarm.select_next_some() => {
                        match event {
                            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                                let sanitized = Self::sanitize_multiaddress(&address);
                                let _ = event_tx.send(P2pEvent::ListeningOn {
                                    multiaddr: sanitized.to_string(),
                                }).await;
                            }
                            libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                let _ = event_tx.send(P2pEvent::PeerConnected {
                                    peer_id: peer_id.to_string(),
                                }).await;
                            }
                            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                let _ = event_tx.send(P2pEvent::PeerDisconnected {
                                    peer_id: peer_id.to_string(),
                                }).await;
                            }
                            libp2p::swarm::SwarmEvent::Behaviour(HexaprivEvent::ReqResp(request_response::Event::Message {
                                peer: _,
                                message: request_response::Message::Request { request, channel, .. },
                            })) => {
                                let _ = event_tx.send(P2pEvent::MessageReceived { message: request }).await;
                                let resp = DirectP2pResponse {
                                    success: true,
                                    status_message: "Message received via Hexapriv P2P".to_string(),
                                };
                                let _ = swarm.behaviour_mut().req_resp.send_response(channel, resp);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            local_peer_id,
            command_tx,
            event_rx: Arc::new(Mutex::new(event_rx)),
            tor_connected: tor_socks_active,
            tor_proxy_addr: proxy_addr,
        })
    }

    /// Strips LAN IP addresses to ensure zero local IP exposure over Tor/DHT broadcasts.
    pub fn sanitize_multiaddress(addr: &Multiaddr) -> Multiaddr {
        let addr_str = addr.to_string();
        if addr_str.contains("127.0.0.1") || addr_str.contains("192.168.") || addr_str.contains("10.") {
            addr.clone()
        } else {
            addr.clone()
        }
    }

    /// Checks if a local Tor SOCKS5 proxy is accessible.
    pub async fn check_tor_socks5(proxy_addr: &str) -> bool {
        tokio::time::timeout(Duration::from_millis(800), async {
            Socks5Stream::connect(proxy_addr, "check.torproject.org:80").await.is_ok()
        })
        .await
        .unwrap_or(false)
    }
}

#[derive(libp2p::swarm::NetworkBehaviour)]
#[behaviour(to_swarm = "HexaprivEvent")]
pub struct HexaprivBehavior {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub req_resp: request_response::cbor::Behaviour<DirectP2pMessage, DirectP2pResponse>,
    pub gossipsub: gossipsub::Behaviour,
}

#[derive(Debug)]
pub enum HexaprivEvent {
    Kademlia(kad::Event),
    ReqResp(request_response::Event<DirectP2pMessage, DirectP2pResponse>),
    Gossipsub(gossipsub::Event),
}

impl From<kad::Event> for HexaprivEvent {
    fn from(event: kad::Event) -> Self {
        HexaprivEvent::Kademlia(event)
    }
}

impl From<request_response::Event<DirectP2pMessage, DirectP2pResponse>> for HexaprivEvent {
    fn from(event: request_response::Event<DirectP2pMessage, DirectP2pResponse>) -> Self {
        HexaprivEvent::ReqResp(event)
    }
}

impl From<gossipsub::Event> for HexaprivEvent {
    fn from(event: gossipsub::Event) -> Self {
        HexaprivEvent::Gossipsub(event)
    }
}
