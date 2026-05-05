package p2p

import (
	"encoding/binary"
	"fmt"
	"io"
)

// StreamChunkSize bounds the per-chunk payload during stream reassembly.
const StreamChunkSize = 32 * 1024

// WriteStream serializes a sized byte stream as:
//
//	[8-byte BE int64 total][repeated: 4-byte BE uint32 chunkLen][chunkLen bytes]
//
// The reader signals end either by EOF or by exhausting the declared total.
func WriteStream(w io.Writer, total int64, src io.Reader) (int64, error) {
	if err := binary.Write(w, binary.BigEndian, total); err != nil {
		return 0, err
	}
	buf := make([]byte, StreamChunkSize)
	var written int64
	for written < total {
		n, err := src.Read(buf)
		if n > 0 {
			if werr := binary.Write(w, binary.BigEndian, uint32(n)); werr != nil {
				return written, werr
			}
			if _, werr := w.Write(buf[:n]); werr != nil {
				return written, werr
			}
			written += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, err
		}
	}
	if written != total {
		return written, fmt.Errorf("short stream: declared %d, sent %d", total, written)
	}
	return written, nil
}

// ReadStream is the inverse of WriteStream. It reads the declared total,
// then reassembles chunks into dst until that total is reached.
func ReadStream(r io.Reader, dst io.Writer) (int64, error) {
	var total int64
	if err := binary.Read(r, binary.BigEndian, &total); err != nil {
		return 0, err
	}
	var read int64
	for read < total {
		var chunkLen uint32
		if err := binary.Read(r, binary.BigEndian, &chunkLen); err != nil {
			return read, err
		}
		if int64(chunkLen) > total-read {
			return read, fmt.Errorf("chunk overruns declared total: chunk=%d remaining=%d", chunkLen, total-read)
		}
		if _, err := io.CopyN(dst, r, int64(chunkLen)); err != nil {
			return read, err
		}
		read += int64(chunkLen)
	}
	return read, nil
}
