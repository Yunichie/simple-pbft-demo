use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Request {
    operation: Vec<u8>,
    timestamp: u64,
    client_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PrePrepare {
    view: u64,
    seq_num: u64,
    digest: [u8; 32],
    request: Request,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Prepare {
    view: u64,
    seq_num: u64,
    digest: [u8; 32],
    replica_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Commit {
    view: u64,
    seq_num: u64,
    digest: [u8; 32],
    replica_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Reply {
    view: u64,
    timestamp: u64,
    client_id: u64,
    replica_id: u32,
    result: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage<T> {
    pub message: T,
    pub signature: Vec<u8>,
    pub signer_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PBFTMessage {
    Request(SignedMessage<Request>),
    PrePrepare(SignedMessage<PrePrepare>),
    Prepare(SignedMessage<Prepare>),
    Commit(SignedMessage<Commit>),
    Reply(SignedMessage<Reply>),
}
