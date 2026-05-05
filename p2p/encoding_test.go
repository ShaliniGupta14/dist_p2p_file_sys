package p2p

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultDecoderMessageRoundtrip(t *testing.T) {
	payload := []byte("the quick brown fox jumps over the lazy dog")

	frame := new(bytes.Buffer)
	frame.WriteByte(IncomingMessage)
	assert.NoError(t, binary.Write(frame, binary.BigEndian, uint32(len(payload))))
	frame.Write(payload)

	var rpc RPC
	assert.NoError(t, DefaultDecoder{}.Decode(frame, &rpc))
	assert.False(t, rpc.Stream)
	assert.Equal(t, payload, rpc.Payload)
}

func TestDefaultDecoderStreamMarker(t *testing.T) {
	frame := bytes.NewReader([]byte{IncomingStream})
	var rpc RPC
	assert.NoError(t, DefaultDecoder{}.Decode(frame, &rpc))
	assert.True(t, rpc.Stream)
	assert.Nil(t, rpc.Payload)
}

func TestDefaultDecoderUnknownType(t *testing.T) {
	frame := bytes.NewReader([]byte{0x9})
	var rpc RPC
	err := DefaultDecoder{}.Decode(frame, &rpc)
	assert.Error(t, err)
}

func TestDefaultDecoderTruncatedLength(t *testing.T) {
	// Type byte but length prefix cut short — must error, not silently accept.
	frame := bytes.NewReader([]byte{IncomingMessage, 0x00, 0x00})
	var rpc RPC
	err := DefaultDecoder{}.Decode(frame, &rpc)
	assert.Error(t, err)
}
