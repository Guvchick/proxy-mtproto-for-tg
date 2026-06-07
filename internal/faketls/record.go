// Package faketls implements the fake-TLS handshake masquerade used by the
// "ee" secret type.  Traffic looks like a TLS 1.3 HTTPS connection to an
// observer, but carries the obfuscated2 MTProto nonce inside.
package faketls

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	recordHandshake    byte = 0x16
	recordChangeCipher byte = 0x20
	recordAppData      byte = 0x17

	maxRecordSize = 16384
)

// readRecord reads one TLS record and returns (type, payload, error).
func readRecord(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[3:5]))
	if length > maxRecordSize {
		return 0, nil, fmt.Errorf("TLS record too large: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

// writeRecord writes a single TLS record.
func writeRecord(w io.Writer, recType byte, payload []byte) error {
	hdr := [5]byte{recType, 0x03, 0x03,
		byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// RecordReader wraps a reader, stripping TLS application-data record headers
// transparently so callers see a plain byte stream.
type RecordReader struct {
	r   io.Reader
	buf []byte
	pos int
}

func NewRecordReader(r io.Reader) *RecordReader { return &RecordReader{r: r} }

func (rr *RecordReader) Read(p []byte) (int, error) {
	for rr.pos >= len(rr.buf) {
		typ, payload, err := readRecord(rr.r)
		if err != nil {
			return 0, err
		}
		if typ != recordAppData {
			return 0, fmt.Errorf("expected app-data record, got 0x%02x", typ)
		}
		rr.buf = payload
		rr.pos = 0
	}
	n := copy(p, rr.buf[rr.pos:])
	rr.pos += n
	return n, nil
}

// RecordWriter wraps a writer, framing bytes into TLS application-data records.
type RecordWriter struct {
	w io.Writer
}

func NewRecordWriter(w io.Writer) *RecordWriter { return &RecordWriter{w: w} }

func (rw *RecordWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxRecordSize {
			chunk = p[:maxRecordSize]
		}
		if err := writeRecord(rw.w, recordAppData, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}
