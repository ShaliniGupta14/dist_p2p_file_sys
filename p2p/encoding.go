package p2p

import (
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
)

type Decoder interface {
	Decode(io.Reader, *RPC) error
}

type GOBDecoder struct{}

func (dec GOBDecoder) Decode(r io.Reader, msg *RPC) error {
	return gob.NewDecoder(r).Decode(msg)
}

// DefaultDecoder reads length-prefixed frames off the wire.
//
// Wire format:
//
//	[1 byte type][...payload]
//
// type == IncomingMessage:  followed by [4-byte BE uint32 length][length bytes payload]
// type == IncomingStream:   no payload here; caller reassembles via ReadStream.
type DefaultDecoder struct{}

func (dec DefaultDecoder) Decode(r io.Reader, msg *RPC) error {
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, typeBuf); err != nil {
		return err
	}

	switch typeBuf[0] {
	case IncomingStream:
		msg.Stream = true
		return nil
	case IncomingMessage:
		var length uint32
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return err
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return err
		}
		msg.Payload = payload
		return nil
	default:
		return fmt.Errorf("unknown frame type: 0x%x", typeBuf[0])
	}
}
