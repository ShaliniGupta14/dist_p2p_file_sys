package main

import (
	"bytes"
	"crypto/sha1"
	"net"
	"testing"

	"github.com/anthdm/foreverstore/p2p"
)

// fakePeer wraps a pair of pipes so sendFileStream / recvFileStream can run
// against an in-memory connection without spinning up TCP listeners.
type fakePeer struct {
	net.Conn
}

func (p *fakePeer) Send(b []byte) error {
	_, err := p.Conn.Write(b)
	return err
}
func (p *fakePeer) CloseStream() {}

func newFakePeerPair() (*fakePeer, *fakePeer) {
	a, b := net.Pipe()
	return &fakePeer{a}, &fakePeer{b}
}

func TestFileStreamRoundtrip(t *testing.T) {
	sender, receiver := newFakePeerPair()
	ciphertext := bytes.Repeat([]byte{0xAB, 0xCD}, 4096)

	done := make(chan error, 1)
	go func() {
		done <- sendFileStream(sender, ciphertext)
	}()

	// recvFileStream reads the IncomingStream marker via DefaultDecoder in the
	// real path; here we strip it manually to mirror the post-marker state.
	hdr := make([]byte, 1)
	if _, err := receiver.Read(hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != p2p.IncomingStream {
		t.Fatalf("expected IncomingStream marker, got 0x%x", hdr[0])
	}

	got, err := recvFileStream(receiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ciphertext) {
		t.Fatalf("ciphertext mismatch: len(want)=%d len(got)=%d", len(ciphertext), len(got))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFileStreamChecksumMismatchRejected(t *testing.T) {
	// Hand-craft a corrupted frame: valid SHA-1 prefix, then ciphertext mutated
	// after the hash was computed. recvFileStream must reject.
	sender, receiver := newFakePeerPair()
	ciphertext := []byte("good ciphertext")

	go func() {
		_ = sendFileStream(sender, ciphertext)
	}()

	hdr := make([]byte, 1)
	if _, err := receiver.Read(hdr); err != nil {
		t.Fatal(err)
	}

	// Drain the stream as the receiver would, then flip a byte and re-feed
	// through recvFileStream's verifier via an in-memory replay.
	got, err := recvFileStream(receiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ciphertext) {
		t.Fatalf("baseline roundtrip failed")
	}

	// Now build a tampered frame manually and feed it to recvFileStream.
	tampered := append([]byte{}, ciphertext...)
	tampered[0] ^= 0xFF
	wire := new(bytes.Buffer)
	// Use sendFileStream's own SHA over the ORIGINAL ciphertext, but transmit
	// the tampered bytes — checksum cannot match.
	originalSum := sha1Sum(ciphertext)
	body := bytes.NewBuffer(nil)
	body.Write(originalSum)
	body.Write(tampered)
	if _, err := p2p.WriteStream(wire, int64(body.Len()), bytes.NewReader(body.Bytes())); err != nil {
		t.Fatal(err)
	}

	mockPeer := &fakePeer{Conn: &readerConn{r: wire}}
	if _, err := recvFileStream(mockPeer); err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
}

// readerConn adapts a bytes.Buffer (or any io.Reader) to net.Conn for tests
// that only need the Read side.
type readerConn struct {
	net.Conn
	r interface {
		Read(p []byte) (int, error)
	}
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func sha1Sum(b []byte) []byte {
	sum := sha1.Sum(b)
	return sum[:]
}
