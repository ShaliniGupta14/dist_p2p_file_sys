# Distributed P2P File System

A storage layer that behaves like a tiny private S3 stretched across a handful of machines: write a file once, it lands on disk locally and replicates to peers; read it back from anywhere, and the system serves it from local disk if it has the bytes, or pulls them from whichever peer does.

Built in Go. Custom binary protocol over raw TCP, AES-256 at rest and in transit, SHA-1 content addressing with end-to-end integrity checks, and a per-key concurrency model.

## Why I built this

I wanted to put my hands on the parts of distributed systems most people only describe at a whiteboard: framing your own protocol on a socket, dealing with the fact that TCP doesn't give you message boundaries, encrypting at rest in a way that survives someone walking off with the disk, and content-addressing files so identical bytes only get stored once.

There are off-the-shelf libraries for every one of those things. The point of the project was to write them — to feel where the corners are.

## What it does

Three nodes form a flat overlay network at startup. They bootstrap by dialing each other and stay connected for the lifetime of the process. From there:

- **`Store(key, reader)`** — encrypts the bytes, writes the ciphertext to local disk under a SHA-1-derived path, then streams the same ciphertext to every connected peer.
- **`Get(key)`** — if local disk has it, decrypt and return. Otherwise broadcast a request, wait for a peer to respond with a ciphertext stream, verify the SHA-1 of the payload, store it, decrypt, return.
- **`Delete(key)`** — removes the local copy. Replicas on peers stay; this is a cache-eviction primitive, not a network-wide unlink.

Files on disk are ciphertext. Plaintext exists only in process memory, only for as long as a caller holds the returned reader.

## Run it

```sh
make test    # unit tests + race detector
make run     # 3-node demo: 20 stores, each followed by a local delete + remote refetch
```

The demo prints what every node is doing — accept loops, bootstrap dials, stream events on each side, ciphertext lengths — so you can watch the protocol work.

---

## Engineering decisions

### Wire protocol

TCP gives you a byte stream, not messages. The first thing this needed was framing. I went with a 1-byte type tag followed by a 4-byte big-endian length:

```
[type byte] [uint32 length] [payload]
```

Two type tags: `0x01` for control messages (gob-encoded RPCs like "store this key" or "give me this key"), `0x02` for file streams. The decoder reads the type byte, branches, and either reads exactly `length` bytes for the message body or hands control to a separate stream reader.

The starting point of this codebase did a fixed-size 1028-byte `Read` on every frame and hoped the message fit. Switching to a real length prefix was the single biggest correctness change in the project — without it, anything larger than 1028 bytes silently corrupts the next frame, and the symptom is "everything works in the demo, nothing works at scale."

### Stream reassembly

For file content I didn't want one giant `io.Copy`, because that couples the receiver's buffer size to the sender's payload. I framed file bodies as a chunked stream:

```
[int64 total]  [uint32 chunkLen] [chunk bytes]
                       repeated until total reached
```

The reader knows the total up front, then reads chunk headers one at a time and reassembles into a destination writer. This gives me natural backpressure (`io.CopyN` per chunk), bounded per-iteration memory, and a way to detect truncation — if a chunk header claims more bytes than the declared total has remaining, the reader rejects rather than producing a partial file.

### Encryption model

AES-256 in CTR mode. Each `Store` generates a fresh 16-byte IV, prepends it to the ciphertext, and the same `[IV || ciphertext]` blob is what gets written to local disk *and* streamed to peers.

I made one significant pivot here. The starting code wrote plaintext to local disk and only encrypted in flight, which means anyone with physical access to a node's disk reads the file directly. I rewrote `Store` to encrypt once into a buffer, then fan the ciphertext out to (a) the local file and (b) the wire. Disk and network see the same bytes. Plaintext lives in RAM only, only at write time and at the moment a `Get` caller is reading.

I considered AES-GCM instead of CTR (AEAD gives you authenticity for free), but I had a separate integrity layer on top of the stream and didn't want to duplicate the work. CTR plus an explicit SHA-1 checksum is simpler to reason about and keeps the IV-handling code trivially auditable.

### Content addressing and deduplication

On-disk paths are derived by SHA-1-hashing the (already hashed) key and slicing the hex digest into 5-character directory segments:

```
ggnetwork/<node-id>/68044/29f74/181a6/3c50c/3d81d/733a1/2f14a/353ff/<filename>
```

This gives the filesystem a CAS-like layout and makes "do we already have this content?" a single `os.Stat`. On `Write`, the store checks for an existing file at the target path and short-circuits if it's there, draining the input reader so the wire stays aligned. A `DedupeHits()` counter exposes how often that fires — useful for tests, useful for any future observability layer.

Honest limitation: the addressing is by *key hash*, not *content hash*. Two different keys with identical bytes still produce two on-disk copies. True content-addressing would mean a second indirection (key → content-hash → bytes), which I judged out of scope for a project this size. The hook is in the right place; only the hash input changes.

### Integrity verification

Every file stream carries a 20-byte SHA-1 of the ciphertext at the head of the body:

```
stream body = [20-byte SHA-1] [ciphertext]
```

The receiver reassembles, splits the prefix off, recomputes SHA-1 over the trailing bytes, and refuses to store on mismatch. A flipped bit anywhere in transit fails the check before the file ever touches disk.

I went back and forth on hashing plaintext vs. ciphertext. Plaintext gives end-to-end integrity (it would catch storage bit-rot too). Ciphertext gives transit integrity and is verifiable without holding the key, which means a peer could one day audit its own cache without privilege. I chose ciphertext for the protocol layer for that reason, and figured that storage bit-rot is detectable on read by comparing against the CAS path's expected hash — a cheaper place to put that check if I ever add it.

### Concurrency

There are two layers of concurrency to think about, and they have different shapes.

**Transport-level multiplexing.** Each accepted or dialed TCP connection runs in its own goroutine. The transport's read loop decodes a frame and either pushes it to a channel for application-level handling or, for stream frames, blocks on a `sync.WaitGroup` until the application handler signals it's done reading the stream body. This is what lets file transfers and control messages share one socket without the read loop racing the application against the same connection.

**Per-key locking on the store.** A coarse global `sync.RWMutex` would have worked but would serialize unrelated reads. I put a `map[key]*sync.RWMutex` behind a master mutex. Reads take the per-key read lock, writes and deletes take the per-key write lock, and the master mutex only guards lookup-or-create of the per-key lock itself. Concurrent writes to *different* keys run in parallel; concurrent operations on the *same* key are correctly serialized.

This shows up clearly in the test suite — 32 goroutines writing 32 distinct keys all complete in parallel under `-race`, while write/delete/write sequences on a single key produce the right final state every time.

### Things I left unfixed

- A `Get` for a key that no peer holds blocks the receive loop. There's no "not found" reply or timeout. Fixing it cleanly requires request/response correlation, which is the next obvious extension.
- The whole ciphertext is buffered in memory on both sides during a transfer. Streaming through `io.Pipe` would make large files practical; for the demo it isn't worth the complexity.
- There's a 5ms `time.Sleep` in `Store` between the metadata broadcast and the stream send. It works because the receiver's read loop is fast, but the proper fix is to have the metadata message carry a "stream incoming" hint and have the handler block on a channel that the read loop signals — replacing a timing assumption with an actual happens-before edge.

I called these out in the code where they live. They're shaped well enough that the next pass — by me or someone else — can address them without rewriting the protocol.

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
