package p2p

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStreamRoundtrip(t *testing.T) {
	// Larger than StreamChunkSize so reassembly does multiple iterations.
	payload := make([]byte, StreamChunkSize*3+1234)
	_, err := rand.Read(payload)
	assert.NoError(t, err)

	wire := new(bytes.Buffer)
	n, err := WriteStream(wire, int64(len(payload)), bytes.NewReader(payload))
	assert.NoError(t, err)
	assert.Equal(t, int64(len(payload)), n)

	out := new(bytes.Buffer)
	read, err := ReadStream(wire, out)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(payload)), read)
	assert.Equal(t, payload, out.Bytes())
}

func TestStreamSingleByte(t *testing.T) {
	wire := new(bytes.Buffer)
	_, err := WriteStream(wire, 1, bytes.NewReader([]byte{0xAB}))
	assert.NoError(t, err)

	out := new(bytes.Buffer)
	_, err = ReadStream(wire, out)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xAB}, out.Bytes())
}

func TestStreamShortSourceErrors(t *testing.T) {
	// Declare 100 bytes but src only has 10 — WriteStream must error.
	wire := new(bytes.Buffer)
	_, err := WriteStream(wire, 100, bytes.NewReader(make([]byte, 10)))
	assert.Error(t, err)
}

func TestReadStreamTruncated(t *testing.T) {
	// Wire claims 50 bytes but stops after one short chunk — ReadStream must error.
	wire := new(bytes.Buffer)
	_, _ = WriteStream(wire, 10, bytes.NewReader(make([]byte, 10)))
	bad := wire.Bytes()[:len(wire.Bytes())-3]

	out := new(bytes.Buffer)
	_, err := ReadStream(bytes.NewReader(bad), out)
	assert.Error(t, err)
}
