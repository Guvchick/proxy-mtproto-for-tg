// Package obfs implements the MTProto obfuscated2 stream cipher layer.
//
// Protocol reference: https://core.telegram.org/mtproto/mtproto-transports#obfuscated
//
// The client sends a 64-byte nonce. Bytes [8:40] and [40:56] are raw key
// material (not encrypted). Bytes [56:64] are AES-256-CTR encrypted using
// keys derived from that material XOR'd with the proxy secret. After
// decryption bytes [56:60] contain the protocol magic and [60:64] the DC ID.
package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Protocol identifies the inner MTProto frame format.
type Protocol int

const (
	ProtocolAbridged     Protocol = iota // 0xef  (1-byte length prefix)
	ProtocolIntermediate                 // 0xeeeeeeee (4-byte length prefix)
	ProtocolPadded                       // 0xdddddddd (padded intermediate)
)

var protoMagic = map[[4]byte]Protocol{
	{0xef, 0xef, 0xef, 0xef}: ProtocolAbridged,
	{0xee, 0xee, 0xee, 0xee}: ProtocolIntermediate,
	{0xdd, 0xdd, 0xdd, 0xdd}: ProtocolPadded,
}

// initTag is what the proxy sends to the Telegram DC to announce the protocol.
var initTag = map[Protocol][]byte{
	ProtocolAbridged:     {0xef},
	ProtocolIntermediate: {0xee, 0xee, 0xee, 0xee},
	ProtocolPadded:       {0xdd, 0xdd, 0xdd, 0xdd},
}

// Cipher wraps a net.Conn with obfuscated2 stream encryption.
type Cipher struct {
	reader   cipher.Stream
	writer   cipher.Stream
	DC       int
	Protocol Protocol
}

// New derives the obfuscated2 cipher from a 64-byte client nonce and the
// proxy secret (16 bytes).
func New(nonce []byte, secret []byte) (*Cipher, error) {
	if len(nonce) < 64 {
		return nil, fmt.Errorf("nonce too short: %d", len(nonce))
	}

	// Derive read cipher (client → proxy direction).
	readKey := deriveKey(nonce[8:40], secret)
	readCipher, err := newCTR(readKey, nonce[40:56])
	if err != nil {
		return nil, err
	}
	// Advance by 56 bytes to align with the encrypted portion of the nonce.
	var skip [56]byte
	readCipher.XORKeyStream(skip[:], skip[:])

	// Decrypt magic[4] + dcID[4] from nonce[56:64].
	var decoded [8]byte
	readCipher.XORKeyStream(decoded[:], nonce[56:64])

	var magic [4]byte
	copy(magic[:], decoded[0:4])
	proto, ok := protoMagic[magic]
	if !ok {
		return nil, fmt.Errorf("unknown protocol magic: %08x", magic)
	}

	// DC IDs are signed int32; negative values are media DCs (same IPs).
	dcRaw := int32(binary.LittleEndian.Uint32(decoded[4:8]))
	dcID := int(dcRaw)
	if dcID < 0 {
		dcID = -dcID
	}
	if dcID < 1 || dcID > 5 {
		return nil, fmt.Errorf("invalid DC ID: %d", dcID)
	}

	// Derive write cipher (proxy → client direction) from reversed nonce.
	rev := reverseBytes(nonce[:64])
	writeKey := deriveKey(rev[8:40], secret)
	writeCipher, err := newCTR(writeKey, rev[40:56])
	if err != nil {
		return nil, err
	}
	writeCipher.XORKeyStream(skip[:], skip[:]) // advance by 56

	return &Cipher{
		reader:   readCipher,
		writer:   writeCipher,
		DC:       dcID,
		Protocol: proto,
	}, nil
}

// InitTag returns the bytes the proxy must send to the DC when opening the
// upstream connection to announce the inner protocol.
func (c *Cipher) InitTag() []byte {
	return initTag[c.Protocol]
}

// NewReader wraps r so that reads decrypt using the read key stream.
func (c *Cipher) NewReader(r io.Reader) io.Reader { return &ctrReader{r: r, s: c.reader} }

// NewWriter wraps w so that writes encrypt using the write key stream.
func (c *Cipher) NewWriter(w io.Writer) io.Writer { return &ctrWriter{w: w, s: c.writer} }

// --- stream wrappers --------------------------------------------------------

type ctrReader struct {
	r io.Reader
	s cipher.Stream
}

func (r *ctrReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.s.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

type ctrWriter struct {
	w   io.Writer
	s   cipher.Stream
	buf []byte
}

func (w *ctrWriter) Write(p []byte) (int, error) {
	if cap(w.buf) < len(p) {
		w.buf = make([]byte, len(p))
	}
	w.buf = w.buf[:len(p)]
	w.s.XORKeyStream(w.buf, p)
	return w.w.Write(w.buf)
}

// --- helpers ----------------------------------------------------------------

func deriveKey(material, secret []byte) []byte {
	h := sha256.New()
	h.Write(material)
	h.Write(secret)
	return h.Sum(nil) // 32 bytes
}

func newCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[len(b)-1-i] = v
	}
	return r
}
