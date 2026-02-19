use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::{
    config::node::NodeConfig,
    crypto::primitives::Crypto,
    message::message_types::{Commit, PBFTMessage, PrePrepare, Prepare, Request, SignedMessage},
    network::network_layer::Network,
    state::app_state::AppState,
};

pub struct Replica {
    node_id: u32,
    f: u32,
    view: u64,
    next_seq_num: u64,
    message_log: HashMap<u64, MessageLog>,
    executed_req: HashSet<u64>,
    last_executed: u64,
    crypto: Crypto,
    app_state: AppState,
}

pub struct MessageLog {
    request: Option<Request>,
    pre_prepare: Option<PrePrepare>,
    prepares: HashMap<u32, Prepare>,
    commits: HashMap<u32, Commit>,
    prepared: bool,
    committed: bool,
}

impl MessageLog {
    fn new() -> Self {
        MessageLog {
            request: None,
            pre_prepare: None,
            prepares: HashMap::new(),
            commits: HashMap::new(),
            prepared: false,
            committed: false,
        }
    }
}

impl Replica {
    pub fn new(node_id: u32, total_nodes: u32, crypto: Crypto) -> Self {
        assert!(total_nodes >= 4);
        assert!((total_nodes - 1) % 3 == 0);

        let f = (total_nodes - 1) / 3;

        Replica {
            node_id,
            f,
            view: 0,
            next_seq_num: 1,
            message_log: HashMap::new(),
            executed_req: HashSet::new(),
            last_executed: 0,
            crypto,
            app_state: AppState::new(),
        }
    }

    fn total_nodes(&self) -> u32 {
        3 * self.f + 1
    }

    pub fn is_primary(&self) -> bool {
        self.node_id as u64 == self.view % (self.total_nodes() as u64)
    }

    fn get_primary(&self) -> u32 {
        (self.view % (self.total_nodes() as u64)) as u32
    }

    fn get_or_create_log(&mut self, seq_num: u64) -> &mut MessageLog {
        self.message_log
            .entry(seq_num)
            .or_insert_with(MessageLog::new)
    }

    fn check_prepared(&mut self, seq_num: u64, digest: &[u8; 32]) {
        let log = self.message_log.get_mut(&seq_num).unwrap();

        if log.prepared {
            return;
        }

        let matching_prepares = log
            .prepares
            .values()
            .filter(|p| &p.digest == digest)
            .count();

        if matching_prepares >= 2 * self.f as usize {
            log.prepared = true;
        }
    }

    fn check_committed(&mut self, seq_num: u64, digest: &[u8; 32]) -> bool {
        let log = self.message_log.get_mut(&seq_num).unwrap();

        if log.committed {
            return true;
        }

        if !log.committed {
            return false;
        }

        let matching_commits = log.commits.values().filter(|p| &p.digest == digest).count();

        if matching_commits == (2 * self.f + 1) as usize {
            log.committed = true;
            return true;
        }

        false
    }

    fn execute_request(&mut self, seq_num: u64) -> Option<Vec<u8>> {
        if seq_num != self.last_executed + 1 {
            return None;
        }

        let log = self.message_log.get(&seq_num)?;
        let req = log.request.as_ref()?;

        if self.executed_req.contains(&req.timestamp) {
            return None;
        }

        let result = self.app_state.execute(&req.operation);

        self.executed_req.insert(req.timestamp);
        self.last_executed = seq_num;
        Some(result)
    }

    fn compute_digest(&self, req: &Request) -> [u8; 32] {
        let serialized = postcard::to_allocvec(req).unwrap();
        let mut hasher = Sha256::new();

        hasher.update(&serialized);

        let res = hasher.finalize();
        let mut digest = [0u8; 32];

        digest.copy_from_slice(&res);
        digest
    }

    async fn handle_request(&mut self, signed_req: SignedMessage<Request>, network: &Network) {
        if !self.is_primary() {
            return;
        }

        let req = signed_req.message;

        if self.executed_req.contains(&req.timestamp) {
            return;
        }

        let seq_num = self.next_seq_num;
        self.next_seq_num += 1;

        let digest = self.compute_digest(&req);

        let pre_prepare = PrePrepare {
            view: self.view,
            seq_num,
            digest,
            request: req.clone(),
        };

        let signed_pre_prepare = self.crypto.create_signed_message(pre_prepare.clone());
        network
            .broadcast(&PBFTMessage::PrePrepare(signed_pre_prepare))
            .await;

        let log = self.get_or_create_log(seq_num);
        log.request = Some(req);
        log.pre_prepare = Some(pre_prepare);

        println!("Primary: broadcasted pre-prepare for seq {}", seq_num);
    }

    async fn handle_pre_prepare(
        &mut self,
        signed_pre_prepare: SignedMessage<PrePrepare>,
        network: &Network,
    ) {
        let pre = signed_pre_prepare.message;

        if !self.validate_pre_prepare(&pre, signed_pre_prepare.signer_id, network) {
            println!("Pre-prepare invalid");
            return;
        }

        // let log = self.get_or_create_log(pre.seq_num);
        // log.request = Some(pre.request.clone());
        // log.pre_prepare = Some(pre.clone());

        let node_id = self.node_id;
        let prepare = Prepare {
            view: pre.view,
            seq_num: pre.seq_num,
            digest: pre.digest,
            replica_id: node_id,
        };

        let signed_prepare = self.crypto.create_signed_message(prepare.clone());

        network
            .broadcast(&PBFTMessage::Prepare(signed_prepare))
            .await;

        let log = self.get_or_create_log(pre.seq_num);
        log.request = Some(pre.request.clone());
        log.pre_prepare = Some(pre.clone());

        log.prepares.insert(node_id, prepare);

        println!("Backup: sent prepare for seq {}", pre.seq_num);
    }

    async fn handle_prepare(&mut self, signed_prepare: SignedMessage<Prepare>, network: &Network) {
        let prepare = signed_prepare.message;

        if !self.validate_prepare(&prepare) {
            return;
        }

        let log = self.get_or_create_log(prepare.seq_num);

        if log.prepares.contains_key(&prepare.replica_id) {
            return;
        }

        log.prepares.insert(prepare.replica_id, prepare.clone());

        println!(
            "Received prepare from {} for seq {} (total: {})",
            prepare.replica_id,
            prepare.seq_num,
            log.prepares.len()
        );

        self.check_prepared(prepare.seq_num, &prepare.digest);

        let log = self.message_log.get_mut(&prepare.seq_num).unwrap();

        if log.prepared && !log.commits.contains_key(&self.node_id) {
            let commit = Commit {
                view: prepare.view,
                seq_num: prepare.seq_num,
                digest: prepare.digest,
                replica_id: self.node_id,
            };

            let signed_commit = self.crypto.create_signed_message(commit.clone());
            network.broadcast(&PBFTMessage::Commit(signed_commit)).await;

            log.commits.insert(self.node_id, commit);

            println!("Prepared! Sent commit for seq {}", prepare.seq_num);
        }
    }

    async fn handle_commit(&mut self, signed_commit: SignedMessage<Commit>, network: &Network) {
        let commit = signed_commit.message;

        if !self.validate_commit(&commit) {
            return;
        }

        let log = self.get_or_create_log(commit.seq_num);

        if log.commits.contains_key(&commit.replica_id) {
            return;
        }

        log.commits.insert(commit.replica_id, commit.clone());

        println!(
            "Received commit from {} for seq {} (total: {})",
            commit.replica_id,
            commit.seq_num,
            log.commits.len()
        );

        if self.check_committed(commit.seq_num, &commit.digest) {
            println!("Committed seq {}!", commit.seq_num);

            self.try_execute_up_to(commit.seq_num);
        }
    }

    fn validate_pre_prepare(
        &mut self,
        pre_prepare: &PrePrepare,
        signer_id: u32,
        network: &Network,
    ) -> bool {
        let expected_primary = self.get_primary();

        if signer_id != expected_primary {
            println!(
                "Pre-prepare not from primary (expected {}, got {})",
                expected_primary, signer_id
            );
            return false;
        }

        if pre_prepare.view != self.view {
            println!(
                "Pre-prepare view mismatch (expected {}, got {})",
                self.view, pre_prepare.view
            );
            return false;
        }

        let digest = self.compute_digest(&pre_prepare.request);
        if digest != pre_prepare.digest {
            println!(
                "Pre-prepare digest mismatch (expected {:?}, got {:?})",
                digest, pre_prepare.digest
            );
            return false;
        }

        if let Some(log) = self.message_log.get(&pre_prepare.seq_num) {
            if let Some(curr) = &log.pre_prepare {
                if curr.digest != pre_prepare.digest {
                    println!("Conflicting pre-prepare for seq {}", pre_prepare.seq_num);
                    return false;
                }
            }
        }

        true
    }

    fn validate_prepare(&self, prepare: &Prepare) -> bool {
        if prepare.view != self.view {
            return false;
        }

        if let Some(log) = self.message_log.get(&prepare.seq_num) {
            if let Some(pre) = &log.pre_prepare {
                return pre.digest == prepare.digest;
            }
        }

        false
    }

    fn validate_commit(&self, commit: &Commit) -> bool {
        if commit.view != self.view {
            return false;
        }

        if let Some(log) = self.message_log.get(&commit.seq_num) {
            if let Some(pre) = &log.pre_prepare {
                if pre.digest != commit.digest {
                    println!("Commit digest mismatch for seq {}", commit.seq_num);
                    return false;
                }
            }
        }

        true
    }

    fn try_execute_up_to(&mut self, target_seq: u64) {
        let mut seq = self.last_executed + 1;

        while seq <= target_seq {
            let is_committed = self
                .message_log
                .get(&seq)
                .map(|log| log.committed)
                .unwrap_or(false);

            if !is_committed {
                break;
            }

            if let Some(res) = self.execute_request(seq) {
                println!(
                    "Executed seq {}: result = {:?}",
                    seq,
                    String::from_utf8_lossy(&res)
                );
            } else {
                println!("Failed to execute seq {}", seq);
                break;
            }

            seq += 1;
        }
    }

    pub async fn run_replica(mut network: Network, mut replica: Replica, mut config: NodeConfig) {
        network.spawn_acceptor();

        for peer in config.peers {
            network.connect_to_peer(peer.id, peer.addr).await;
        }

        println!(
            "Replica {} started (primary: {})",
            replica.node_id,
            replica.is_primary()
        );

        loop {
            if let Some(msg) = network.recv().await {
                if !replica.crypto.verify_pbft_message(&msg) {
                    continue;
                }

                match msg {
                    PBFTMessage::Request(req) => {
                        replica.handle_request(req, &network).await;
                    }
                    PBFTMessage::PrePrepare(pp) => {
                        replica.handle_pre_prepare(pp, &network).await;
                    }
                    PBFTMessage::Prepare(p) => {
                        replica.handle_prepare(p, &network).await;
                    }
                    PBFTMessage::Commit(c) => {
                        replica.handle_commit(c, &network).await;
                    }
                    PBFTMessage::Reply(_) => {}
                }
            }
        }
    }
}
