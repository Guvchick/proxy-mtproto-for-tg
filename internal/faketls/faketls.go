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
	digestOffset    = 28              // session_id[28:32] carries the 4-byte HMAC digest
	timestampWindow = 3600 * time.Second // ±1 h replay-protection window
)

// clientHello holds the parts of the ClientHello we care about.
type clientHello struct {
	random    [32]byte
	sessionID [32]byte
	sni       string
	raw       []byte // complete raw TLS record (type + version + length + body)
}

// Handshake performs the fake-TLS masquerade.
//
// It reads the client's ClientHello, validates the SNI and HMAC digest,
// then sends a fake ServerHello / ChangeCipherSpec, and finally reads the
// client's ApplicationData record which contains the 64-byte obfuscated2
// nonce.
//
// The returned nonce is fed directly into obfs.New.
func Handshake(conn net.Conn, secret []byte, domain string) (nonce []byte, err error) {
	ch, err := parseClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("faketls: parse ClientHello: %w", err)
	}

	if domain != "" && ch.sni != domain {
		return nil, fmt.Errorf("faketls: SNI mismatch: got %q, want %q", ch.sni, domain)
	}

	if err := checkDigest(ch, secret); err != nil {
		return nil, fmt.Errorf("faketls: HMAC digest: %w", err)
	}

	ts := time.Unix(int64(binary.BigEndian.Uint32(ch.random[0:4])), 0)
	if diff := time.Since(ts); diff > timestampWindow || diff < -timestampWindow {
		return nil, fmt.Errorf("faketls: timestamp drift too large: %v", diff)
	}

	if err := sendServerHandshake(conn, ch.sessionID); err != nil {
		return nil, fmt.Errorf("faketls: send server handshake: %w", err)
	}

	// Expect client ChangeCipherSpec (6 bytes: 5-byte record header + 0x01).
	var ccs [6]byte
	if _, err := io.ReadFull(conn, ccs[:]); err != nil {
		return nil, fmt.Errorf("faketls: read ChangeCipherSpec: %w", err)
	}
	if ccs[0] != recordChangeCipher {
		return nil, fmt.Errorf("faketls: expected ChangeCipherSpec, got 0x%02x", ccs[0])
	}

	// ApplicationData record contains the obfuscated2 nonce (exactly 64 bytes).
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
	// Read TLS record header (5 bytes).
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

	// Skip handshake header (type[1] + length[3]).
	data := body[4:]

	// Legacy version (2 bytes).
	if len(data) < 2 {
		return nil, fmt.Errorf("ClientHello truncated at version")
	}
	data = data[2:]

	// Random (32 bytes).
	if len(data) < 32 {
		return nil, fmt.Errorf("ClientHello truncated at random")
	}
	copy(ch.random[:], data[:32])
	data = data[32:]

	// Session ID.
	if len(data) < 1 {
		return nil, fmt.Errorf("ClientHello truncated at session_id length")
	}
	sidLen := int(data[0])
	data = data[1:]
	if len(data) < sidLen {
		return nil, fmt.Errorf("ClientHello truncated at session_id")
	}
	if sidLen == sessionIDLen {
		copy(ch.sessionID[:], data[:sidLen])
	}
	data = data[sidLen:]

	// Cipher suites.
	if len(data) < 2 {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < csLen {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites")
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
	if len(data) < 2 {
		return ch, nil // no extensions — that's OK
	}
	extTotal := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < extTotal {
		return nil, fmt.Errorf("ClientHello truncated at extensions")
	}
	ch.sni = extractSNI(data[:extTotal])
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
// The client computes HMAC-SHA256(SHA256(secret), modified_record) where
// modified_record is the full ClientHello with session_id[28:32] zeroed out.
func checkDigest(ch *clientHello, secret []byte) error {
	key := sha256.Sum256(secret)

	// Position of the digest within the raw record:
	// record_hdr(5) + hs_hdr(4) + legacy_version(2) + random(32) + sid_len(1) + digestOffset(28)
	const digestPos = 5 + 4 + 2 + 32 + 1 + digestOffset
	if len(ch.raw) < digestPos+4 {
		return fmt.Errorf("record too short to contain digest")
	}

	saved := make([]byte, 4)
	copy(saved, ch.raw[digestPos:digestPos+4])

	// Zero out digest in a copy.
	raw := make([]byte, len(ch.raw))
	copy(raw, ch.raw)
	copy(raw[digestPos:digestPos+4], []byte{0, 0, 0, 0})

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
	// Fake ApplicationData: 36 zero bytes (mirrors what real TLS 1.3 servers send).
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
	body := []byte{0x03, 0x03} // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)    // server random
	body = append(body, byte(sessionIDLen))
	body = append(body, sessionID[:]...)
	body = append(body, 0x13, 0x02) // TLS_AES_256_GCM_SHA384
	body = append(body, 0x00)       // compression: null

	// Extensions: supported_versions → TLS 1.3
	exts := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	// Handshake header.
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, handshakeServerHello)
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record.
	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, recordHandshake, 0x03, 0x03,
		byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}
