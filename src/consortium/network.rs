//! gRPC over mutual TLS around the state machine.
//!
//! Inbound, a message has to clear three checks before the protocol sees it. The TLS layer checks that the
//! peer's certificate chains to the consortium's CA. The service checks that the certificate's hash is the
//! one the roster lists for the claimed sender. And both an Ed25519 and an ML-DSA-65 signature have to cover
//! this consortium, sender, recipient and payload, so that a recorded message cannot be replayed to a different
//! node, and so that forging one takes breaking both algorithms.

use super::consent::{ConsentSource, EvmConsentSource, FileConsentLedger};
use super::core::{ConsortiumCore, Message, NodeStatus};
use super::roster::{ConsentConfig, NodeConfig, Roster};
use crate::signatures::{verify, HybridSignature, HybridSigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tokio_mpsc;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response, Status};

#[allow(clippy::all)]
mod proto {
    tonic::include_proto!("medcrypto.consortium.v1");
}

use proto::consortium_node_client::ConsortiumNodeClient;
use proto::consortium_node_server::{ConsortiumNode, ConsortiumNodeServer};
use proto::{Ack, Envelope, StatusReply, StatusRequest};

/// A Galois key share at the larger preset is over 100 MiB.
const MAX_MESSAGE_BYTES: usize = 1 << 30;
/// How long a message is retried for a peer that stays down, after which it is dropped with a log line.
const RETRY_WINDOW: Duration = Duration::from_secs(3600);

fn signed_bytes(consortium: &str, sender: &str, recipient: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = b"medcrypto-consortium-envelope-v1".to_vec();
    for part in [
        consortium.as_bytes(),
        sender.as_bytes(),
        recipient.as_bytes(),
    ] {
        out.extend_from_slice(&(part.len() as u64).to_le_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&Sha256::digest(payload));
    out
}

const SIGNATURE_CONTEXT: &[u8] = b"medcrypto-consortium-envelope";

/// Both signatures on a message have to hold, for the node that the roster says sent it.
fn check_envelope(
    roster: &Roster,
    sender: &str,
    me: &str,
    envelope: &Envelope,
) -> Result<(), Status> {
    let node = roster
        .node(sender)
        .ok_or_else(|| Status::permission_denied("the sender is not in the roster"))?;
    let signed = signed_bytes(&roster.consortium_id, sender, me, &envelope.payload);
    let signature = HybridSignature {
        ed25519: envelope.signature.clone(),
        ml_dsa_65: envelope.pq_signature.clone(),
    };
    if verify(
        &node.signing_public_key,
        SIGNATURE_CONTEXT,
        &signed,
        &signature,
    ) {
        Ok(())
    } else {
        Err(Status::unauthenticated("bad signature"))
    }
}

struct NodeService {
    roster: Arc<Roster>,
    me: String,
    events: mpsc::Sender<(String, Message)>,
    status: Arc<Mutex<NodeStatus>>,
}

impl NodeService {
    fn authenticate<T>(
        &self,
        request: &Request<T>,
        claimed: Option<&str>,
    ) -> Result<String, Status> {
        let certificates = request
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("no client certificate"))?;
        let certificate = certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("no client certificate"))?;
        let hash = hex::encode(Sha256::digest(certificate.as_ref()));
        let node = self
            .roster
            .nodes
            .iter()
            .find(|n| n.cert_sha256 == hash)
            .ok_or_else(|| Status::permission_denied("this certificate is not in the roster"))?;
        if claimed.is_some_and(|c| c != node.id) {
            return Err(Status::permission_denied(
                "the sender does not match the certificate",
            ));
        }
        Ok(node.id.clone())
    }
}

#[tonic::async_trait]
impl ConsortiumNode for NodeService {
    async fn deliver(&self, request: Request<Envelope>) -> Result<Response<Ack>, Status> {
        let claimed = request.get_ref().sender.clone();
        let sender = self.authenticate(&request, Some(&claimed))?;
        let envelope = request.into_inner();
        if envelope.recipient != self.me {
            return Err(Status::permission_denied(
                "this message is for another node",
            ));
        }
        check_envelope(&self.roster, &sender, &self.me, &envelope)?;
        let message: Message = postcard::from_bytes(&envelope.payload)
            .map_err(|e| Status::invalid_argument(format!("undecodable message: {e}")))?;
        self.events
            .send((sender, message))
            .map_err(|_| Status::unavailable("shutting down"))?;
        Ok(Response::new(Ack {}))
    }

    async fn status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusReply>, Status> {
        self.authenticate(&request, None)?;
        let status = self.status.lock().expect("not poisoned").clone();
        Ok(Response::new(StatusReply {
            node_id: self.me.clone(),
            keys_ready: status.keys_ready,
            jobs_running: status.running,
            jobs_finished: status.finished,
            jobs_failed: status.failed,
        }))
    }
}

fn client_tls(config: &NodeConfig, peer: &str) -> Result<ClientTlsConfig, String> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{p:?}: {e}"));
    Ok(ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(read(&config.ca_cert)?))
        .identity(Identity::from_pem(read(&config.cert)?, read(&config.key)?))
        .domain_name(peer))
}

async fn connect(endpoint: &str, tls: ClientTlsConfig) -> Result<Channel, String> {
    Endpoint::from_shared(endpoint.to_string())
        .map_err(|e| e.to_string())?
        .tls_config(tls)
        .map_err(|e| e.to_string())?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .map_err(|e| e.to_string())
}

/// Delivers one peer's messages in order, retrying through outages.
async fn peer_sender(
    peer: String,
    endpoint: String,
    tls: ClientTlsConfig,
    mut queue: tokio_mpsc::UnboundedReceiver<Envelope>,
) {
    let mut client: Option<ConsortiumNodeClient<Channel>> = None;
    while let Some(envelope) = queue.recv().await {
        let deadline = Instant::now() + RETRY_WINDOW;
        let mut delay = Duration::from_millis(200);
        loop {
            if client.is_none() {
                match connect(&endpoint, tls.clone()).await {
                    Ok(channel) => {
                        client = Some(
                            ConsortiumNodeClient::new(channel)
                                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                                .max_encoding_message_size(MAX_MESSAGE_BYTES),
                        );
                    }
                    Err(e) => {
                        if Instant::now() > deadline {
                            eprintln!("[daemon] gave up on a message for {peer}: {e}");
                            break;
                        }
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(15));
                        continue;
                    }
                }
            }
            let call = client
                .as_mut()
                .expect("connected above")
                .deliver(envelope.clone());
            match call.await {
                Ok(_) => break,
                // The peer has read this and refused it, and sending it again would not help.
                Err(status)
                    if matches!(
                        status.code(),
                        tonic::Code::PermissionDenied
                            | tonic::Code::Unauthenticated
                            | tonic::Code::InvalidArgument
                    ) =>
                {
                    eprintln!("[daemon] {peer} refused a message: {status}");
                    break;
                }
                Err(status) => {
                    client = None;
                    if Instant::now() > deadline {
                        eprintln!("[daemon] gave up on a message for {peer}: {status}");
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(15));
                }
            }
        }
    }
}

/// A running daemon.
pub struct DaemonHandle {
    shutdown: tokio::sync::watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), String>>,
    status: Arc<Mutex<NodeStatus>>,
    worker: Option<std::thread::JoinHandle<()>>,
    stop_worker: Arc<std::sync::atomic::AtomicBool>,
}

impl DaemonHandle {
    pub fn status(&self) -> NodeStatus {
        self.status.lock().expect("not poisoned").clone()
    }

    /// Stops serving, and waits for the protocol thread to end.
    pub async fn stop(mut self) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        self.stop_worker
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let served = self.server.await.map_err(|e| e.to_string())?;
        if let Some(worker) = self.worker.take() {
            let _ = tokio::task::spawn_blocking(move || worker.join()).await;
        }
        served
    }
}

fn consent_source(config: &ConsentConfig) -> Result<Box<dyn ConsentSource>, String> {
    Ok(match config {
        ConsentConfig::File { path } => Box::new(FileConsentLedger::new(path)),
        ConsentConfig::Evm { rpc_url, contract } => {
            Box::new(EvmConsentSource::new(rpc_url, contract)?)
        }
    })
}

/// Starts a node. Returns once it is listening, and keeps running until stopped.
pub async fn run_daemon(config: NodeConfig) -> Result<DaemonHandle, String> {
    let roster = Arc::new(Roster::load(&config.roster)?);
    let me = roster
        .node(&config.node_id)
        .ok_or_else(|| format!("{} is not in the roster", config.node_id))?
        .clone();
    let read = |p: &Path| std::fs::read(p).map_err(|e| format!("{p:?}: {e}"));

    // A roster that does not list this node's actual certificate could not talk to anyone.
    let certificate = read(&config.cert)?;
    let parsed = pem_to_der(&certificate)?;
    if hex::encode(Sha256::digest(&parsed)) != me.cert_sha256 {
        return Err(format!(
            "{:?} is not the certificate the roster lists",
            config.cert
        ));
    }

    let seed_text = std::fs::read_to_string(&config.signing_key).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = hex::decode(seed_text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the signing key is not 32 bytes of hex")?;
    let signing = HybridSigningKey::from_seed(&seed);
    if signing.public_key() != &me.signing_public_key {
        return Err("the signing key is not the one the roster lists".to_string());
    }

    let (events_tx, events_rx) = mpsc::channel::<(String, Message)>();
    let status = Arc::new(Mutex::new(NodeStatus::default()));

    let mut peers: BTreeMap<String, tokio_mpsc::UnboundedSender<Envelope>> = BTreeMap::new();
    for peer in roster.nodes.iter().filter(|n| n.id != me.id) {
        let (tx, rx) = tokio_mpsc::unbounded_channel();
        peers.insert(peer.id.clone(), tx);
        tokio::spawn(peer_sender(
            peer.id.clone(),
            peer.endpoint.clone(),
            client_tls(&config, &peer.id)?,
            rx,
        ));
    }

    let mut core = ConsortiumCore::new(
        (*roster).clone(),
        &me.id,
        config.data_dir.clone(),
        config.studies.clone(),
        consent_source(&config.consent)?,
    )?;
    let stop_worker = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker = {
        let stop = stop_worker.clone();
        let status = status.clone();
        let roster = roster.clone();
        let me_id = me.id.clone();
        let poll = Duration::from_secs(config.poll_seconds.max(1));
        std::thread::spawn(move || {
            if let Err(e) = core.start() {
                eprintln!("[daemon] {me_id}: key generation could not start: {e}");
                return;
            }
            let flush = |core: &mut ConsortiumCore| {
                for outgoing in core.take_outgoing() {
                    let payload = match postcard::to_allocvec(&outgoing.message) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[daemon] {me_id}: {e}");
                            continue;
                        }
                    };
                    let signature = match signing.sign(
                        SIGNATURE_CONTEXT,
                        &signed_bytes(&roster.consortium_id, &me_id, &outgoing.to, &payload),
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("[daemon] {me_id}: could not sign: {e}");
                            continue;
                        }
                    };
                    if let Some(peer) = peers.get(&outgoing.to) {
                        let _ = peer.send(Envelope {
                            sender: me_id.clone(),
                            recipient: outgoing.to.clone(),
                            payload,
                            signature: signature.ed25519,
                            pq_signature: signature.ml_dsa_65,
                        });
                    }
                }
                *status.lock().expect("not poisoned") = core.status();
            };
            flush(&mut core);
            let mut last_tick: Option<Instant> = None;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                match events_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok((sender, message)) => {
                        if let Err(e) = core.handle(&sender, message) {
                            eprintln!("[daemon] {me_id}: from {sender}: {e}");
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if last_tick.is_none_or(|t| t.elapsed() >= poll) {
                    last_tick = Some(Instant::now());
                    for problem in core.tick() {
                        eprintln!("[daemon] {me_id}: {problem}");
                    }
                }
                flush(&mut core);
            }
        })
    };

    let identity = Identity::from_pem(read(&config.cert)?, read(&config.key)?);
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(read(&config.ca_cert)?));
    let service = ConsortiumNodeServer::new(NodeService {
        roster: roster.clone(),
        me: me.id.clone(),
        events: events_tx,
        status: status.clone(),
    })
    .max_decoding_message_size(MAX_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_MESSAGE_BYTES);
    let address: std::net::SocketAddr = config
        .listen
        .parse()
        .map_err(|e| format!("{}: {e}", config.listen))?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|e| format!("{address}: {e}"))?;
    let (shutdown, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let router = Server::builder()
        .tls_config(tls)
        .map_err(|e| e.to_string())?
        .add_service(service);
    let server = tokio::spawn(async move {
        router
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async move {
                    let _ = shutdown_rx.changed().await;
                },
            )
            .await
            .map_err(|e| e.to_string())
    });
    Ok(DaemonHandle {
        shutdown,
        server,
        status,
        worker: Some(worker),
        stop_worker,
    })
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(pem).map_err(|e| e.to_string())?;
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE"))
        .collect();
    decode_base64(&body).ok_or_else(|| "the certificate is not valid PEM".to_string())
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = text.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut word = 0u32;
        for &c in chunk {
            word = word << 6 | value(c)?;
        }
        word <<= 6 * (4 - chunk.len()) as u32;
        out.extend_from_slice(&word.to_be_bytes()[1..chunk.len()]);
    }
    Some(out)
}

/// Asks a node how it is doing, as one of the consortium's members.
pub async fn query_status(config: &NodeConfig, target: &str) -> Result<StatusReply, String> {
    let roster = Roster::load(&config.roster)?;
    let node = roster
        .node(target)
        .ok_or_else(|| format!("{target} is not in the roster"))?;
    let channel = connect(&node.endpoint, client_tls(config, target)?).await?;
    let reply = ConsortiumNodeClient::new(channel)
        .status(StatusRequest {})
        .await
        .map_err(|e| e.to_string())?;
    Ok(reply.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consortium::roster::RosterNode;

    fn setup() -> (Roster, HybridSigningKey) {
        let key = HybridSigningKey::from_seed(&[3; 32]);
        let roster = Roster {
            consortium_id: "c".into(),
            threshold_k: 1,
            poly_degree: 8192,
            crs_seed: "00".repeat(32),
            smudging_bits: 24,
            nodes: vec![RosterNode {
                id: "a".into(),
                party: 1,
                endpoint: "https://127.0.0.1:1".into(),
                cert_sha256: "00".repeat(32),
                signing_public_key: key.public_key().clone(),
            }],
        };
        (roster, key)
    }

    fn envelope(
        key: &HybridSigningKey,
        consortium: &str,
        recipient: &str,
        payload: &[u8],
    ) -> Envelope {
        let signature = key
            .sign(
                SIGNATURE_CONTEXT,
                &signed_bytes(consortium, "a", recipient, payload),
            )
            .unwrap();
        Envelope {
            sender: "a".into(),
            recipient: recipient.into(),
            payload: payload.to_vec(),
            signature: signature.ed25519,
            pq_signature: signature.ml_dsa_65,
        }
    }

    #[test]
    fn an_envelope_needs_both_signatures_and_the_right_addressee() {
        let (roster, key) = setup();
        let good = envelope(&key, "c", "b", b"payload");
        assert!(check_envelope(&roster, "a", "b", &good).is_ok());

        // A quantum attacker who can forge Ed25519 still has to get past ML-DSA, and the reverse.
        let mut no_pq = good.clone();
        no_pq.pq_signature = Vec::new();
        assert!(check_envelope(&roster, "a", "b", &no_pq).is_err());
        let mut no_classical = good.clone();
        no_classical.signature = Vec::new();
        assert!(check_envelope(&roster, "a", "b", &no_classical).is_err());

        let mut tampered = good.clone();
        tampered.payload = b"changed".to_vec();
        assert!(check_envelope(&roster, "a", "b", &tampered).is_err());

        // A recorded message cannot be replayed to another node, or in another consortium.
        assert!(check_envelope(&roster, "a", "c", &good).is_err());
        assert!(
            check_envelope(&roster, "a", "b", &envelope(&key, "other", "b", b"payload")).is_err()
        );

        // A key that is not the roster's does not count, and neither does a sender who is not in it.
        let stranger = HybridSigningKey::from_seed(&[4; 32]);
        assert!(check_envelope(
            &roster,
            "a",
            "b",
            &envelope(&stranger, "c", "b", b"payload")
        )
        .is_err());
        assert!(check_envelope(&roster, "nobody", "b", &good).is_err());
    }
}
