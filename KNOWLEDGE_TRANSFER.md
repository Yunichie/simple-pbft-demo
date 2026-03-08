# Knowledge Transfer: Simple PBFT Demo

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [What is PBFT?](#2-what-is-pbft)
3. [Architecture Overview](#3-architecture-overview)
4. [Module-by-Module Walkthrough](#4-module-by-module-walkthrough)
5. [Consensus Flow: Step-by-Step](#5-consensus-flow-step-by-step)
6. [Key Data Structures](#6-key-data-structures)
7. [How to Build and Run](#7-how-to-build-and-run)
8. [Current Limitations & Potential Improvements](#8-current-limitations--potential-improvements)

---

## 1. Project Overview

This is an **educational Rust implementation** of the **Practical Byzantine Fault Tolerance (PBFT)** consensus algorithm. It was created as a learning exercise to understand how PBFT works in practice. The system runs a 4-node network on localhost, where nodes communicate over QUIC (a modern UDP-based transport protocol), sign messages with Ed25519 digital signatures, and reach consensus on client requests using the classic PBFT three-phase protocol.

**Tech Stack:**
- **Language:** Rust (edition 2024)
- **Async Runtime:** Tokio
- **Transport:** QUIC via the `quinn` crate
- **TLS:** `rustls` (with self-signed certificates, verification skipped for demo purposes)
- **Cryptography:** `ring` (Ed25519 signing/verification), `sha2` (SHA-256 digests)
- **Serialization:** `postcard` (a compact `no_std`-friendly `serde` format)

---

## 2. What is PBFT?

### The Byzantine Generals Problem
In distributed systems, nodes may fail in arbitrary ways—they can crash, send conflicting messages, or act maliciously. These are called **Byzantine faults**. The Byzantine Generals Problem asks: how can a group of distributed processes reach agreement even when some of them are faulty?

### PBFT in a Nutshell
PBFT (proposed by Castro and Liskov, 1999) is a consensus protocol that guarantees **safety** (all honest nodes agree on the same result) and **liveness** (the system makes progress) as long as **fewer than 1/3 of the nodes are faulty**. For `n` total nodes and `f` faulty nodes:

```
n = 3f + 1
```

So with **4 nodes**, the system tolerates **1 Byzantine (malicious/faulty) node**.

### The Three Phases
PBFT consensus proceeds in three phases after a client sends a request:

```
Client → Primary → All Replicas → All Replicas → Execute
         (Pre-Prepare)  (Prepare)     (Commit)
```

1. **Pre-Prepare:** The primary (leader) assigns a sequence number to the request and broadcasts a `PrePrepare` message to all backup replicas.
2. **Prepare:** Each backup validates the `PrePrepare`, then broadcasts a `Prepare` message to all other replicas. Once a replica collects **2f** matching `Prepare` messages, the request is considered **prepared**.
3. **Commit:** Once prepared, each replica broadcasts a `Commit` message. Once a replica collects **2f+1** matching `Commit` messages, the request is considered **committed** and is executed.

### View Changes
If the primary is faulty (e.g., it stops sending messages), replicas can initiate a **view change** to elect a new primary. The new primary is determined by: `primary = view_number % total_nodes`.

---

## 3. Architecture Overview

### Directory Structure

```
simple-pbft-demo/
├── Cargo.toml              # Project manifest (dependencies, build config)
├── README.md               # Brief project description (EN + JP)
├── .gitignore              # Ignores /target, Cargo.lock, /keys
└── src/
    ├── lib.rs              # Library root — re-exports all modules
    ├── main.rs             # Binary: PBFT node (takes node_id as CLI arg)
    ├── bin/
    │   ├── keygen.rs       # Binary: generates Ed25519 key pairs for all 4 nodes
    │   └── client.rs       # Binary: sends a single request to the primary node
    ├── config/
    │   └── node.rs         # Hardcoded network topology (4 nodes on localhost)
    ├── config.rs            # Module declaration for config/
    ├── crypto/
    │   └── primitives.rs   # Ed25519 signing, verification, key loading
    ├── crypto.rs            # Module declaration for crypto/
    ├── message/
    │   └── message_types.rs # All PBFT message type definitions
    ├── message.rs           # Module declaration for message/
    ├── network/
    │   ├── cert.rs         # TLS certificate generation and config
    │   └── network_layer.rs # QUIC networking: connect, send, receive, broadcast
    ├── network.rs           # Module declaration for network/
    ├── state/
    │   ├── app_state.rs    # Simple key-value store (the "application")
    │   └── replica.rs      # Core PBFT logic: consensus state machine
    └── state.rs             # Module declaration for state/
```

### Three Binaries

| Binary | Command | Purpose |
|--------|---------|---------|
| `keygen` | `cargo run --bin keygen` | Generates Ed25519 key pairs for 4 nodes, saves to `keys/` directory |
| `node` | `cargo run --bin node -- <id>` | Starts a PBFT replica node (id: 0-3). Node 0 is the initial primary |
| `client` | `cargo run --bin client -- '<operation>'` | Sends a request to the primary (e.g., `'PUT:name:Alice'`) |

### Component Relationships

```
┌─────────┐     QUIC      ┌─────────┐
│ Client  │───────────────▶│  Node 0 │ (Primary)
└─────────┘                │ Replica │
                           └────┬────┘
                                │ broadcasts PrePrepare
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
              ┌─────────┐ ┌─────────┐ ┌─────────┐
              │  Node 1 │ │  Node 2 │ │  Node 3 │
              │ Replica │ │ Replica │ │ Replica │
              └─────────┘ └─────────┘ └─────────┘
                    │           │           │
                    └───────────┼───────────┘
                          Prepare + Commit
                          messages between
                          all replicas
```

---

## 4. Module-by-Module Walkthrough

### 4.1 `config/node.rs` — Network Topology

**Purpose:** Defines the hardcoded network configuration for the 4-node cluster.

**Key Types:**
- `NodeConfig` — contains a node's bind address and list of peers
- `PeerConfig` — a peer's id and socket address

**Key Function:**
- `get_node_config(node_id: u32) -> NodeConfig` — returns the config for a given node. All 4 nodes listen on `127.0.0.1:5000-5003`. Each node's peer list excludes itself.

```
Node 0: binds 127.0.0.1:5000, peers = [1, 2, 3]
Node 1: binds 127.0.0.1:5001, peers = [0, 2, 3]
Node 2: binds 127.0.0.1:5002, peers = [0, 1, 3]
Node 3: binds 127.0.0.1:5003, peers = [0, 1, 2]
```

### 4.2 `crypto/primitives.rs` — Cryptography

**Purpose:** Handles Ed25519 key generation, message signing, and signature verification.

**Key Type: `Crypto`**
```rust
pub struct Crypto {
    keypair: Ed25519KeyPair,      // This node's private key
    id: u32,                       // This node's ID
    peer_public_keys: HashMap<u32, Vec<u8>>,  // Known peers' public keys
}
```

**Key Methods:**
| Method | What It Does |
|--------|-------------|
| `generate_keypair()` | Creates a new Ed25519 key pair (PKCS#8 format) |
| `sign<T: Serialize>(message)` | Serializes a message with `postcard` then signs with Ed25519 |
| `create_signed_message<T>(message)` | Wraps a message with its signature and the signer's ID |
| `verify_signed_message<T>(signed_msg)` | Looks up the signer's public key and verifies the signature |
| `verify_pbft_message(message)` | Dispatches to the correct verifier based on message type. **Note:** For `Request` messages from unknown clients, it accepts them without verification (demo convenience) |

**Key Function:**
- `setup_crypto_for_node(node_id)` — Loads this node's private key and all peers' public keys from the `keys/` directory. Panics if keys are missing.

### 4.3 `message/message_types.rs` — Protocol Messages

**Purpose:** Defines all the data types used in the PBFT protocol.

**Core Message Types:**

| Type | Fields | Role in PBFT |
|------|--------|-------------|
| `Request` | `operation`, `timestamp`, `client_id` | Client's operation to execute |
| `PrePrepare` | `view`, `seq_num`, `digest`, `request` | Primary assigns sequence number |
| `Prepare` | `view`, `seq_num`, `digest`, `replica_id` | Replica confirms it saw the PrePrepare |
| `Commit` | `view`, `seq_num`, `digest`, `replica_id` | Replica confirms the request is prepared |
| `Reply` | `view`, `timestamp`, `client_id`, `replica_id`, `result` | Result sent back to client (defined but not sent in current impl) |
| `ViewChange` | `new_view`, `prepared_requests`, `replica_id` | Initiates leader change |
| `NewView` | `new_view`, `view_change_msgs`, `pre_prepares`, `replica_id` | New leader confirms the view change |

**Wrapper Types:**
- `SignedMessage<T>` — wraps any message `T` with a `signature` and `signer_id`
- `PreparedProof` — a `PrePrepare` plus its matching `Prepare` messages (used in view changes)
- `PBFTMessage` — the top-level enum that wraps all signed message types for network transmission

### 4.4 `network/cert.rs` — TLS Certificates

**Purpose:** Generates self-signed TLS certificates for QUIC connections.

**Key Type: `NodeCert`** — holds the DER-encoded certificate and private key.

**Key Functions:**
- `NodeCert::generate(node_id)` — creates a self-signed certificate with subject `node-{id}`
- `make_server_config(certs)` — creates a `rustls::ServerConfig` (no client auth)
- `make_client_config()` — creates a `rustls::ClientConfig` that **skips all certificate verification** (the `SkipVerification` struct). This is acceptable for a local demo but would be a security concern in production.

### 4.5 `network/network_layer.rs` — QUIC Networking

**Purpose:** Manages all network communication between nodes using the QUIC protocol.

**Key Type: `Network`**
```rust
pub struct Network {
    node_id: u32,
    endpoint: Endpoint,                              // QUIC endpoint
    peers: Arc<RwLock<HashMap<u32, Connection>>>,    // Connected peers
    tx: UnboundedSender<PBFTMessage>,                // Channel sender for incoming messages
    rx: UnboundedReceiver<PBFTMessage>,              // Channel receiver for incoming messages
    total_nodes: u32,
}
```

**Key Methods:**
| Method | What It Does |
|--------|-------------|
| `new(node_id, bind_addr, certs, total_nodes)` | Creates a QUIC endpoint that acts as both server and client |
| `spawn_acceptor()` | Spawns a background task that accepts incoming connections and reads messages |
| `connect_to_peer_with_timeout(peer_id, addr)` | Connects to a peer with a 5-second timeout |
| `broadcast(message)` | Sends a message to all connected peers |
| `recv()` | Receives the next incoming message from the channel |

**Wire Format:** Messages are length-prefixed:
```
[4 bytes: message length (big-endian u32)] [N bytes: postcard-serialized PBFTMessage]
```

**Connection Flow:**
1. Each node binds a QUIC endpoint on its port
2. `spawn_acceptor()` starts listening for incoming connections in a background task
3. For each incoming connection, a handler task reads unidirectional streams
4. Received messages are deserialized and sent to the `tx` channel
5. The replica's main loop reads from `rx` via `recv()`

### 4.6 `state/app_state.rs` — Application State Machine

**Purpose:** A simple key-value store that represents the "application" being replicated.

**Key Type: `AppState`** — wraps a `HashMap<String, String>`.

**Supported Operations (as byte strings):**
| Operation | Format | Example | Response |
|-----------|--------|---------|----------|
| PUT | `PUT:<key>:<value>` | `PUT:name:Alice` | `OK` |
| GET | `GET:<key>` | `GET:name` | The value, or `NOT_FOUND` |
| Invalid | anything else | `HELLO` | `INVALID_OPERATION` |

### 4.7 `state/replica.rs` — Core PBFT Consensus Logic ⭐

This is the **heart of the implementation**. It contains the full PBFT state machine.

**Key Type: `Replica`**
```rust
pub struct Replica {
    node_id: u32,
    f: u32,                                          // Max faulty nodes (= 1 for 4 nodes)
    view: u64,                                       // Current view number
    next_seq_num: u64,                               // Next sequence number (primary only)
    message_log: HashMap<u64, MessageLog>,            // Per-sequence-number log
    executed_req: HashSet<u64>,                       // Timestamps of executed requests
    last_executed: u64,                               // Last executed sequence number
    crypto: Crypto,                                  // Signing/verification
    app_state: AppState,                             // The replicated key-value store
    // View change fields (implemented but not yet wired into main loop):
    view_change_timer: Option<Instant>,
    view_change_timeout: Duration,
    in_view_change: bool,
    view_change_msgs: HashMap<u64, HashMap<u32, ViewChange>>,
}
```

**Key Type: `MessageLog`** — per-sequence-number state:
```rust
pub struct MessageLog {
    request: Option<Request>,
    pre_prepare: Option<PrePrepare>,
    prepares: HashMap<u32, Prepare>,    // replica_id → Prepare
    commits: HashMap<u32, Commit>,      // replica_id → Commit
    prepared: bool,                     // True when 2f matching Prepares received
    committed: bool,                    // True when 2f+1 matching Commits received
}
```

**Core Methods (Consensus):**

| Method | Phase | What It Does |
|--------|-------|-------------|
| `handle_request()` | — | Primary only: assigns seq_num, computes digest, broadcasts PrePrepare |
| `handle_pre_prepare()` | Phase 1 | Backup validates PrePrepare, stores it, broadcasts Prepare |
| `handle_prepare()` | Phase 2 | Stores Prepare; if 2f matching Prepares → mark prepared, broadcast Commit |
| `handle_commit()` | Phase 3 | Stores Commit; if 2f+1 matching Commits → mark committed, execute |
| `check_prepared()` | — | Checks if 2f Prepare messages match the digest |
| `check_committed()` | — | Checks if 2f+1 Commit messages match the digest |
| `execute_request()` | — | Executes the operation on AppState if it's the next in sequence |
| `try_execute_up_to()` | — | Executes all committed requests in order up to target seq |

**Validation Methods:**

| Method | What It Checks |
|--------|---------------|
| `validate_pre_prepare()` | Signer is the expected primary, view matches, digest is correct, no conflicting PrePrepare |
| `validate_prepare()` | View matches, digest matches the stored PrePrepare |
| `validate_commit()` | View matches, digest matches the stored PrePrepare |

**Primary Selection:**
```rust
fn is_primary(&self) -> bool {
    self.node_id as u64 == self.view % (self.total_nodes() as u64)
}
```
At view 0, node 0 is primary. At view 1, node 1 is primary, etc.

**Main Event Loop (`run_replica`):**
```rust
loop {
    if let Some(msg) = network.recv().await {
        // 1. Verify the message signature
        if !replica.crypto.verify_pbft_message(&msg) { continue; }
        // 2. Dispatch to the appropriate handler
        match msg {
            PBFTMessage::Request(req) => replica.handle_request(req, &network).await,
            PBFTMessage::PrePrepare(pp) => replica.handle_pre_prepare(pp, &network).await,
            PBFTMessage::Prepare(p) => replica.handle_prepare(p, &network).await,
            PBFTMessage::Commit(c) => replica.handle_commit(c, &network).await,
            // ViewChange and NewView are defined but not dispatched yet
            _ => {}
        }
    }
}
```

### 4.8 `bin/keygen.rs` — Key Generation Utility

Generates Ed25519 key pairs for all 4 nodes and stores them in the `keys/` directory:
- `keys/node_0.key` (private key, PKCS#8 DER)
- `keys/node_0.pub` (public key, raw bytes)
- ... through `node_3`

Skips generation if keys already exist.

### 4.9 `bin/client.rs` — Client Binary

A standalone client that:
1. Generates an ephemeral Ed25519 key pair (client_id = 999)
2. Creates a `Request` message with the operation from the command line
3. Signs it and wraps it as a `PBFTMessage::Request`
4. Connects to the primary (hardcoded to `127.0.0.1:5000`) via QUIC
5. Sends the message using the same length-prefixed wire format
6. Waits 2 seconds and exits (does not read a reply)

### 4.10 `main.rs` — Node Binary Entry Point

1. Installs the `rustls` crypto provider (ring)
2. Parses the node ID from command-line args (must be 0-3)
3. Loads config, crypto keys, and generates a TLS certificate
4. Creates a `Network` and starts listening
5. Waits 5 seconds for other nodes to start
6. Connects to all peers (with retries)
7. Calls `Replica::run_replica()` to enter the main event loop

---

## 5. Consensus Flow: Step-by-Step

Here is the complete flow when a client sends `PUT:name:Alice`:

### Step 1: Client Sends Request
```
Client (bin/client.rs):
  → Creates Request { operation: "PUT:name:Alice", timestamp: <microseconds>, client_id: 999 }
  → Signs it → SignedMessage<Request>
  → Wraps in PBFTMessage::Request
  → Sends to primary (Node 0) over QUIC
```

### Step 2: Primary Receives and Pre-Prepares
```
Node 0 (Primary):
  ← Receives PBFTMessage::Request
  → Verifies signature (accepts unknown clients in demo mode)
  → Assigns seq_num = 1
  → Computes digest = SHA-256(postcard::serialize(request))
  → Creates PrePrepare { view: 0, seq_num: 1, digest, request }
  → Signs it → SignedMessage<PrePrepare>
  → Broadcasts PBFTMessage::PrePrepare to Nodes 1, 2, 3
  → Stores request and pre_prepare in message_log[1]
```

### Step 3: Backups Validate and Prepare
```
Nodes 1, 2, 3 (each independently):
  ← Receives PBFTMessage::PrePrepare
  → Verifies signature (must be from Node 0, the expected primary)
  → Validates: view matches, digest is correct, no conflicting PrePrepare
  → Creates Prepare { view: 0, seq_num: 1, digest, replica_id: self }
  → Signs it → SignedMessage<Prepare>
  → Broadcasts PBFTMessage::Prepare to all peers
  → Stores pre_prepare and own prepare in message_log[1]
```

### Step 4: Collecting Prepares → "Prepared"
```
All Nodes:
  ← Receives Prepare messages from other replicas
  → Validates: view matches, digest matches stored PrePrepare
  → Stores in message_log[1].prepares
  → Checks: do we have ≥ 2f (= 2) matching Prepares?
     YES → Mark as "prepared"
  → Creates Commit { view: 0, seq_num: 1, digest, replica_id: self }
  → Signs and broadcasts PBFTMessage::Commit
```

### Step 5: Collecting Commits → "Committed" → Execute
```
All Nodes:
  ← Receives Commit messages from other replicas
  → Validates: view matches, digest matches
  → Stores in message_log[1].commits
  → Checks: do we have ≥ 2f+1 (= 3) matching Commits?
     YES → Mark as "committed"
  → Executes: app_state.execute("PUT:name:Alice") → "OK"
  → Prints: "Executed seq 1: result = OK"
```

### Quorum Summary
```
Total nodes (n) = 4
Max faulty (f)  = 1

Prepared requires:  2f     = 2 matching Prepares
Committed requires: 2f + 1 = 3 matching Commits
```

---

## 6. Key Data Structures

### Message Nesting
```
PBFTMessage (enum — the network-level message)
 └─ SignedMessage<T> (generic wrapper)
     ├─ message: T        (the actual PBFT message)
     ├─ signature: Vec<u8> (Ed25519 signature over postcard-serialized T)
     └─ signer_id: u32    (which node signed this)
```

### Per-Sequence-Number Log
```
MessageLog (one per sequence number)
 ├─ request: Option<Request>           (the original client request)
 ├─ pre_prepare: Option<PrePrepare>    (from the primary)
 ├─ prepares: HashMap<u32, Prepare>    (from each replica, keyed by replica_id)
 ├─ commits: HashMap<u32, Commit>      (from each replica, keyed by replica_id)
 ├─ prepared: bool                     (set when 2f Prepares match)
 └─ committed: bool                    (set when 2f+1 Commits match)
```

### Replica State Machine
```
Replica
 ├─ node_id, f, view              (identity and consensus params)
 ├─ next_seq_num                   (primary: next sequence to assign)
 ├─ message_log                    (all per-sequence logs)
 ├─ executed_req                   (set of executed request timestamps)
 ├─ last_executed                  (sequence number of last executed request)
 ├─ crypto                         (signing/verification)
 ├─ app_state                      (the replicated key-value store)
 └─ view_change_*                  (view change state — not yet active in main loop)
```

---

## 7. How to Build and Run

### Prerequisites
- Rust toolchain (edition 2024 — requires a recent nightly or stable Rust)

### Step 1: Generate Keys
```bash
cargo run --bin keygen
```
This creates `keys/node_0.key`, `keys/node_0.pub`, ..., `keys/node_3.key`, `keys/node_3.pub`.

### Step 2: Start All 4 Nodes (in separate terminals)
```bash
# Terminal 1
cargo run --bin node -- 0

# Terminal 2
cargo run --bin node -- 1

# Terminal 3
cargo run --bin node -- 2

# Terminal 4
cargo run --bin node -- 3
```

Each node waits 5 seconds after starting, then connects to peers. Node 0 is the primary (leader) in view 0.

### Step 3: Send a Client Request
```bash
# In a 5th terminal:
cargo run --bin client -- 'PUT:name:Alice'
```

You should see all 4 nodes go through the Pre-Prepare → Prepare → Commit → Execute cycle, each printing:
```
Executed seq 1: result = "OK"
```

### Step 4: Send More Requests
```bash
cargo run --bin client -- 'PUT:color:blue'
cargo run --bin client -- 'GET:name'
```

---

## 8. Current Limitations & Potential Improvements

### What's Implemented ✅
- [x] Full 3-phase PBFT consensus (PrePrepare, Prepare, Commit)
- [x] Ed25519 digital signatures on all messages
- [x] Signature verification for all message types
- [x] SHA-256 request digests
- [x] QUIC-based networking with length-prefixed messages
- [x] Simple key-value store as the replicated application
- [x] Primary selection based on view number
- [x] Sequential request execution (ordered by sequence number)
- [x] Duplicate request detection (by timestamp)
- [x] Client binary for sending requests
- [x] Key generation utility
- [x] View change message types and handling logic (code exists)

### What's Not Yet Wired Up ⚠️
- [ ] **View change dispatching** — `ViewChange` and `NewView` messages are defined and handler methods exist, but they are **not dispatched** in the main event loop (`run_replica`). The `match` arms for these message types are empty.
- [ ] **Reply to client** — The `Reply` message type is defined but never sent back to the client. The client sends a request and exits after 2 seconds without reading a response.
- [ ] **View change timer** — Timer fields exist on `Replica` (`view_change_timer`, `view_change_timeout`) and methods exist (`start_timer`, `check_timeout`, `trigger_view_change`), but they are never called from the main loop.

### Potential Improvements 🔧
1. **Wire up view changes** — Dispatch `ViewChange` and `NewView` in the main loop; add timer-based view change triggering.
2. **Reply to clients** — Send `Reply` messages back after execution; have the client wait and collect replies.
3. **Configurable node count** — Currently hardcoded to 4 nodes. Could be made configurable.
4. **Persistent storage** — State is entirely in-memory; restarts lose all data.
5. **Checkpointing & garbage collection** — Add periodic checkpoints to prune old message logs.
6. **Proper TLS verification** — Replace `SkipVerification` with real certificate verification.
7. **Error handling** — Many places use `unwrap()`/`panic!()` that could use proper error handling.
8. **Tests** — No unit or integration tests exist. Adding tests for the consensus logic, crypto, and app state would be valuable.
9. **Logging** — Replace `println!` with a structured logging framework (e.g., `tracing`).
10. **Bug in `compute_new_view_pre_prepares`** — Line 237 has `if seen_seq.contains(&seq)` which should likely be `if !seen_seq.contains(&seq)`. The current code only processes a sequence number if it was already seen (i.e., duplicates), when it should process sequence numbers that have *not* been seen yet (i.e., new entries).

### Code Quality Notes
- The project compiles with several warnings (unused variables, unused imports, dead code) — these are typical for a work-in-progress educational project.
- The `run_replica` method in `main.rs` calls `network.spawn_acceptor()` again even though it was already called in `main()`, resulting in duplicate acceptor tasks.
