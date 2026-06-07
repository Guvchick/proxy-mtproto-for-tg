package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	handshakeClientHello byte = 0x01
	handshakeServerHello byte = 0x02

	sessionIDLen    = 32
	digestOffset    = 28                // session_id[28:32] carries the HMAC digest
	timestampWindow = 3600 * time.Second // ±1 h replay-protection window
)

// Options controls optional checks during the fake-TLS handshake.
type Options struct {
	// SkipHMAC disables the 4-byte HMAC-SHA256 check in session_id.
	// Use only for debugging — makes replay attacks trivial.
	SkipHMAC bool

	// SkipTimestamp disables the ±1 h timestamp drift check.
	SkipTimestamp bool
}

// clientHello holds the parts of the ClientHello we care about.
type clientHello struct {
	random    [32]byte
	sessionID [32]byte
	sni       string
	raw       []byte // complete raw TLS record (header + body)
	digestPos int    // byte offset of the 4-byte HMAC digest within raw
}

// Handshake performs the fake-TLS masquerade.
//
// domain — SNI that the client is expected to send; empty string means "accept any SNI".
//
// Returns the 64-byte obfuscated2 nonce for feeding into obfs.New.
func Handshake(conn net.Conn, secret []byte, domain string, opts Options) (nonce []byte, err error) {
	ch, err := parseClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("faketls: parse ClientHello: %w", err)
	}

	// SNI check — empty domain means "self-SNI / accept all".
	if domain != "" && ch.sni != domain {
		return nil, fmt.Errorf("faketls: SNI mismatch: got %q, want %q", ch.sni, domain)
	}

	if !opts.SkipHMAC {
		if err := checkDigest(ch, secret); err != nil {
			return nil, fmt.Errorf("faketls: HMAC digest: %w", err)
		}
	}

	if !opts.SkipTimestamp {
		ts := time.Unix(int64(binary.BigEndian.Uint32(ch.random[0:4])), 0)
		if diff := time.Since(ts); diff > timestampWindow || diff < -timestampWindow {
			return nil, fmt.Errorf("faketls: timestamp drift too large: %v", diff)
		}
	}

	if err := sendServerHandshake(conn, ch.sessionID); err != nil {
		return nil, fmt.Errorf("faketls: send server handshake: %w", err)
	}

	// Client sends ChangeCipherSpec (6 bytes).
	var ccs [6]byte
	if _, err := io.ReadFull(conn, ccs[:]); err != nil {
		return nil, fmt.Errorf("faketls: read ChangeCipherSpec: %w", err)
	}
	if ccs[0] != recordChangeCipher {
		return nil, fmt.Errorf("faketls: expected ChangeCipherSpec, got 0x%02x", ccs[0])
	}

	// ApplicationData record contains the obfuscated2 nonce (64 bytes).
	recType, payload, err := readRecord(conn)
	if err != nil {
		return nil, fmt.Errorf("faketls: read nonce record: %w", err)
	}
	if recType != recordAppData {
		return nil, fmt.Errorf("faketls: expected AppData, got 0x%02x", recType)
	}
	if len(payload) < 64 {
		return nil, fmt.Errorf("faketls: nonce too short: %d", len(payload))
	}
	return payload[:64], nil
}

// --- parse ClientHello -------------------------------------------------------

func parseClientHello(r io.Reader) (*clientHello, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != recordHandshake {
		return nil, fmt.Errorf("expected handshake record, got 0x%02x", hdr[0])
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if bodyLen > maxRecordSize {
		return nil, fmt.Errorf("record too large: %d", bodyLen)
	}

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	ch := &clientHello{}
	ch.raw = make([]byte, 5+bodyLen)
	copy(ch.raw[:5], hdr[:])
	copy(ch.raw[5:], body)

	if len(body) < 4 || body[0] != handshakeClientHello {
		return nil, fmt.Errorf("expected ClientHello, got 0x%02x", body[0])
	}

	// rawCursor tracks how many bytes we've consumed in ch.raw (starts after record header).
	rawCursor := 5

	// Handshake header: type(1) + length(3).
	rawCursor += 4
	data := body[4:]

	// Legacy version (2 bytes).
	if len(data) < 2 {
		return nil, fmt.Errorf("ClientHello truncated at version")
	}
	rawCursor += 2
	data = data[2:]

	// Random (32 bytes).
	if len(data) < 32 {
		return nil, fmt.Errorf("ClientHello truncated at random")
	}
	copy(ch.random[:], data[:32])
	rawCursor += 32
	data = data[32:]

	// Session ID length (1 byte) + session ID.
	if len(data) < 1 {
		return nil, fmt.Errorf("ClientHello truncated at session_id length")
	}
	sidLen := int(data[0])
	rawCursor++ // consume the length byte
	data = data[1:]
	if len(data) < sidLen {
		return nil, fmt.Errorf("ClientHello truncated at session_id")
	}
	if sidLen == sessionIDLen {
		copy(ch.sessionID[:], data[:sidLen])
		// Digest is at sessionID[28:32] → raw position rawCursor+28.
		ch.digestPos = rawCursor + digestOffset
	}
	rawCursor += sidLen
	data = data[sidLen:]

	// Cipher suites.
	if len(data) < 2 {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < csLen {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites data")
	}
	data = data[csLen:]

	// Compression methods.
	if len(data) < 1 {
		return nil, fmt.Errorf("ClientHello truncated at compression")
	}
	compLen := int(data[0])
	data = data[1:]
	if len(data) < compLen {
		return nil, fmt.Errorf("ClientHello truncated at compression methods")
	}
	data = data[compLen:]

	// Extensions.
	if len(data) >= 2 {
		extTotal := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		if len(data) >= extTotal {
			ch.sni = extractSNI(data[:extTotal])
		}
	}

	return ch, nil
}

func extractSNI(exts []byte) string {
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[:2])
		ln := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < ln {
			break
		}
		if typ == 0x0000 { // server_name
			return parseSNIExt(exts[:ln])
		}
		exts = exts[ln:]
	}
	return ""
}

func parseSNIExt(data []byte) string {
	// list_length(2) + name_type(1) + name_length(2) + name
	if len(data) < 5 || data[2] != 0x00 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+nameLen {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

// --- digest validation -------------------------------------------------------

// checkDigest validates the 4-byte HMAC-SHA256 embedded in session_id[28:32].
//
// The client computes HMAC-SHA256(SHA256(secret), record_with_zeroed_digest)[:4]
// and places it at session_id[28:32].
func checkDigest(ch *clientHello, secret []byte) error {
	if ch.digestPos == 0 {
		return fmt.Errorf("session_id not found or wrong length")
	}
	if len(ch.raw) < ch.digestPos+4 {
		return fmt.Errorf("record too short for digest at %d", ch.digestPos)
	}

	key := sha256.Sum256(secret)

	saved := make([]byte, 4)
	copy(saved, ch.raw[ch.digestPos:ch.digestPos+4])

	raw := make([]byte, len(ch.raw))
	copy(raw, ch.raw)
	copy(raw[ch.digestPos:ch.digestPos+4], []byte{0, 0, 0, 0})

	mac := hmac.New(sha256.New, key[:])
	mac.Write(raw)
	expected := mac.Sum(nil)[:4]

	if !bytes.Equal(saved, expected) {
		return fmt.Errorf("digest mismatch")
	}
	return nil
}

// --- server handshake --------------------------------------------------------

func sendServerHandshake(w io.Writer, sessionID [32]byte) error {
	serverHello := buildServerHello(sessionID)
	changeCipher := []byte{recordChangeCipher, 0x03, 0x03, 0x00, 0x01, 0x01}
	var fakePayload [36]byte
	appData := make([]byte, 0, 5+36)
	appData = append(appData,
		recordAppData, 0x03, 0x03,
		byte(len(fakePayload)>>8), byte(len(fakePayload)))
	appData = append(appData, fakePayload[:]...)

	buf := make([]byte, 0, len(serverHello)+len(changeCipher)+len(appData))
	buf = append(buf, serverHello...)
	buf = append(buf, changeCipher...)
	buf = append(buf, appData...)
	_, err := w.Write(buf)
	return err
}

func buildServerHello(sessionID [32]byte) []byte {
	body := []byte{0x03, 0x03}          // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...) // server random
	body = append(body, byte(sessionIDLen))
	body = append(body, sessionID[:]...)
	body = append(body, 0x13, 0x02) // TLS_AES_256_GCM_SHA384
	body = append(body, 0x00)       // compression: null

	exts := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04} // supported_versions: TLS 1.3
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, handshakeServerHello)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, recordHandshake, 0x03, 0x03,
		byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}
