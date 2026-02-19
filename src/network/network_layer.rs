use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::{collections::HashMap, io::Error, net::SocketAddr, sync::Arc};
use tokio::sync::{
    RwLock,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{
    message::message_types::PBFTMessage,
    network::cert::{NodeCert, make_client_config, make_server_config},
};

pub struct Network {
    node_id: u32,
    endpoint: Endpoint,
    peers: Arc<RwLock<HashMap<u32, Connection>>>,
    tx: UnboundedSender<PBFTMessage>,
    rx: UnboundedReceiver<PBFTMessage>,
    total_nodes: u32,
}

impl Network {
    fn new(node_id: u32, bind_addr: SocketAddr, node_cert: &NodeCert, total_nodes: u32) -> Self {
        let server_cfg = make_server_config(node_cert);
        let client_cfg = make_client_config();
        let mut endpoint = Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_cfg).unwrap(),
            )),
            bind_addr,
        )
        .unwrap();

        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_cfg).unwrap(),
        )));

        let (tx, rx) = mpsc::unbounded_channel();

        Network {
            node_id,
            endpoint,
            peers: Arc::new(RwLock::new(HashMap::new())),
            tx,
            rx,
            total_nodes,
        }
    }

    async fn connect_to_peer(&self, peer_id: u32, peer_addr: SocketAddr) {
        let connection = self
            .endpoint
            .connect(peer_addr, "peer")
            .unwrap()
            .await
            .expect("Failed to connect to peer");

        let mut peers = self.peers.write().await;
        peers.insert(peer_id, connection);
    }

    fn spawn_acceptor(&self) {
        let endpoint = self.endpoint.clone();
        let tx = self.tx.clone();

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let connection = incoming.await.expect("Failed to accept connection");
                let tx = tx.clone();

                tokio::spawn(async move {
                    Self::handle_connection(connection, tx);
                });
            }
        });
    }

    async fn handle_connection(connection: Connection, tx: UnboundedSender<PBFTMessage>) {
        while let Ok(mut recv_stream) = connection.accept_uni().await {
            let inbound_tx = tx.clone();
            tokio::spawn(async move {
                if let Some(msg) = Self::read_message(&mut recv_stream).await {
                    let _ = inbound_tx.send(msg);
                }
            });
        }
    }

    async fn read_message(stream: &mut RecvStream) -> Option<PBFTMessage> {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await.ok()?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.ok()?;

        postcard::from_bytes(&buf).ok()
    }

    async fn send_to(&self, peer_id: u32, message: &PBFTMessage) {
        let peers = self.peers.read().await;
        if let Some(connection) = peers.get(&peer_id) {
            if let Ok(mut send_stream) = connection.open_uni().await {
                let _ = Self::write_message(&mut send_stream, message).await;
                let _ = send_stream.finish();
            }
        }
    }

    pub async fn broadcast(&self, message: &PBFTMessage) {
        let peers = self.peers.read().await;
        for (peer_id, connection) in peers.iter() {
            if let Ok(mut send_stream) = connection.open_uni().await {
                let _ = Self::write_message(&mut send_stream, message).await;
                let _ = send_stream.finish();
            }
        }
    }

    async fn write_message(stream: &mut SendStream, message: &PBFTMessage) {
        if let Ok(serialized) = postcard::to_allocvec(message) {
            let len = serialized.len() as u32;

            let _ = stream.write_all(&len.to_be_bytes()).await;
            let _ = stream.write_all(&serialized).await;
        }
    }

    async fn recv(&mut self) -> Option<PBFTMessage> {
        self.rx.recv().await
    }

    pub fn total_nodes(&self) -> u32 {
        4
    }
}
