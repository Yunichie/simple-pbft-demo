use rand::seq;
use std::collections::{HashMap, HashSet};

use crate::{
    crypto::primitives::Crypto,
    message::message_types::{Commit, PrePrepare, Prepare, Request},
    state::app_state::AppState,
};

struct Replica {
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
    fn new(node_id: u32, total_nodes: u32, crypto: Crypto) -> Self {
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

    fn is_primary(&self, total_nodes: u32) -> bool {
        self.node_id as u64 == self.view % (total_nodes as u64)
    }

    fn get_primary(&self, total_nodes: u32) -> u32 {
        (self.view % (total_nodes as u64)) as u32
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
}
