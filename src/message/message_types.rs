use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub operation: Vec<u8>,
    pub timestamp: u64,
    pub client_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrePrepare {
    pub view: u64,
    pub seq_num: u64,
    pub digest: [u8; 32],
    pub request: Request,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prepare {
    pub view: u64,
    pub seq_num: u64,
    pub digest: [u8; 32],
    pub replica_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub view: u64,
    pub seq_num: u64,
    pub digest: [u8; 32],
    pub replica_id: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reply {
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
