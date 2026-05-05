# Distributed P2P File System

A storage layer across a handful of machines: write a file once, it replicates to peers; read it back from anywhere, served from local disk or pulled from a peer that has it.

Built in Go. Custom binary protocol over raw TCP, AES-256 at rest and in transit, SHA-1 content addressing, per-key concurrency.

## Why

I wanted to put my hands on the parts of distributed systems most people only describe at a whiteboard — framing a protocol on a raw socket, encrypting at rest in a way that survives physical disk theft, content-addressing so identical bytes don't get stored twice. There are off-the-shelf libraries for all of it. The point was to write them.

## What it does

Three nodes form a flat overlay at startup. They bootstrap by dialing each other and stay connected for the lifetime of the process.

- **`Store(key, reader)`** — encrypts, writes ciphertext to local disk under a SHA-1-derived path, streams to every peer.
- **`Get(key)`** — serves from local disk if present; otherwise broadcasts, waits for a peer to respond, verifies SHA-1, stores locally, decrypts, returns.
- **`Delete(key)`** — evicts the local copy. Peer replicas stay — this is cache eviction, not a network-wide unlink.

Plaintext exists only in process memory, only while a caller holds the returned reader.

## Run it

```sh
make test    # unit tests + race detector
make run     # 3-node demo: 20 stores, each followed by a local delete + remote refetch
```

The demo logs what every node is doing — bootstrap dials, stream events, ciphertext lengths — so you can watch the protocol work.

---

## Engineering notes

**Wire protocol.** TCP gives you a byte stream, not messages. Framing is a 1-byte type tag + 4-byte big-endian length prefix. Two types: `0x01` for gob-encoded control messages, `0x02` for file streams. The original codebase did a fixed-size 1028-byte `Read` per frame and hoped messages fit — switching to a real length prefix was the single biggest correctness change, since anything over 1028 bytes silently corrupted the next frame.

**Stream reassembly.** File bodies are chunked: `[int64 total] [uint32 chunkLen] [bytes]...`. The reader knows the total up front and reassembles chunk by chunk — natural backpressure, bounded memory per iteration, and truncation detection (a chunk header claiming more bytes than the declared total has left gets rejected).

**Encryption.** AES-256-CTR. Each `Store` generates a fresh 16-byte IV, prepends it to the ciphertext, and that same blob is what hits local disk *and* the wire. The original code wrote plaintext to disk and only encrypted in-flight — I rewrote `Store` to encrypt once into a buffer and fan ciphertext out to both destinations. Chose CTR over GCM because I had a separate SHA-1 integrity layer and didn't want to duplicate authenticity handling.

**Content addressing.** On-disk paths derive from SHA-1-hashing the key, sliced into 5-char directory segments. Makes "do we have this?" a single `os.Stat`. On write, if the path exists the store short-circuits and drains the reader to keep the wire aligned. Note: addressing is by *key hash*, not content hash — two keys with identical bytes still produce two copies. The hook is in the right place; only the hash input would need to change.

**Integrity.** Every stream carries a 20-byte SHA-1 of the ciphertext at the head. The receiver recomputes after reassembly and refuses to store on mismatch. Hashing ciphertext rather than plaintext means a peer could audit its own cache without needing the decryption key.

**Concurrency.** Two layers. Transport-level: each TCP connection runs in its own goroutine; stream frames block the read loop on a `sync.WaitGroup` until the application handler finishes reading. Store-level: `map[key]*sync.RWMutex` behind a master mutex — concurrent writes to different keys run in parallel, operations on the same key are serialized. 32 goroutines writing 32 distinct keys complete in parallel under `-race`.

**Known gaps.** A `Get` for a key no peer holds blocks the receive loop indefinitely — proper fix needs request/response correlation. The full ciphertext is buffered in memory during transfer — `io.Pipe` would make large files practical. There's a 5ms sleep in `Store` between the metadata broadcast and stream send that should be an explicit happens-before channel signal instead.

---

## Layout

```
main.go                demo: 3-node ring, store + delete-locally + fetch-from-network
server.go              FileServer: Store / Get / replication, message handlers
store.go               CAS storage, encryption-aware writes, dedupe, per-key locks
crypto.go              AES-256-CTR encrypt/decrypt + ID generation
p2p/transport.go       Peer / Transport interfaces
p2p/tcp_transport.go   TCP transport, accept/dial loops, per-conn goroutine
p2p/encoding.go        Length-prefixed message decoder
p2p/framing.go         WriteStream / ReadStream — chunked reassembly
p2p/message.go         RPC type, frame-type constants
```
