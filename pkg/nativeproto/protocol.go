package nativeproto

import (
	"encoding/binary"
	"io"
)

// ReadMessage reads a length-prefixed message from the given reader.
// Format: 4-byte little-endian length followed by JSON payload.
func ReadMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// WriteMessage writes a length-prefixed message to the given writer.
func WriteMessage(w io.Writer, payload []byte) error {
	length := uint32(len(payload))
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return err
	}

	_, err := w.Write(payload)
	return err
}
