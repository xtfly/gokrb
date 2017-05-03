package gokrb

import (
	"encoding/binary"
	"io"
)

// SendToken send token to service
func SendToken(conn io.Writer, buf []byte) error {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(buf)))
	_, err := conn.Write(b)
	if err != nil {
		return err
	}
	conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

// RecvToken recive from a token from service
func RecvToken(conn io.ReadWriter) ([]byte, error) {
	b := make([]byte, 4)
	_, err := conn.Read(b)
	if err != nil {
		return b, err
	}

	size := binary.BigEndian.Uint32(b)
	buf := make([]byte, size)
	_, err = conn.Read(buf)

	return buf, err
}
