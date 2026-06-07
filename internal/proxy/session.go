package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/guvchick/mtproto-proxy/internal/dc"
	"github.com/guvchick/mtproto-proxy/internal/faketls"
	"github.com/guvchick/mtproto-proxy/internal/obfs"
	"github.com/guvchick/mtproto-proxy/internal/relay"
	"github.com/guvchick/mtproto-proxy/internal/secret"
	"github.com/guvchick/mtproto-proxy/internal/telemetry"
)

// session handles a single client connection end-to-end.
type session struct {
	conn    net.Conn
	sec     *secret.Secret
	family  dc.AddrFamily
	metrics *telemetry.Metrics
	log     *slog.Logger
	bufSize int
}

func (s *session) handle() {
	defer s.conn.Close()

	clientAddr := s.conn.RemoteAddr().String()
	log := s.log.With("client", clientAddr)

	s.metrics.TotalConnections.Inc()
	s.metrics.ActiveConnections.Inc()
	defer s.metrics.ActiveConnections.Dec()

	// Step 1: perform the handshake (optionally fake-TLS, then obfuscated2).
	cipher, err := s.handshake(log)
	if err != nil {
		log.Debug("handshake failed", "err", err)
		s.metrics.RejectedConnections.Inc()
		s.metrics.HandshakeErrors.WithLabelValues(errReason(err)).Inc()
		return
	}

	log = log.With("dc", cipher.DC, "proto", cipher.Protocol)
	log.Debug("handshake ok")
	s.metrics.ConnectionsByDC.WithLabelValues(fmt.Sprintf("%d", cipher.DC)).Inc()

	// Step 2: connect to the Telegram DC.
	dcConn, err := dc.Dial(cipher.DC, s.family)
	if err != nil {
		log.Warn("dial DC failed", "err", err)
		s.metrics.RejectedConnections.Inc()
		return
	}
	defer dcConn.Close()

	// Step 3: send protocol init tag to DC.
	if _, err := dcConn.Write(cipher.InitTag()); err != nil {
		log.Warn("write init tag failed", "err", err)
		return
	}

	// Step 4: relay bidirectionally.
	//
	// For fake-TLS connections the client-facing streams are additionally
	// wrapped in TLS application-data records.
	var clientRead io.Reader
	var clientWrite io.Writer

	if s.sec.Type == secret.TypeFakeTLS {
		clientRead = cipher.NewReader(faketls.NewRecordReader(s.conn))
		clientWrite = cipher.NewWriter(faketls.NewRecordWriter(s.conn))
	} else {
		clientRead = cipher.NewReader(s.conn)
		clientWrite = cipher.NewWriter(s.conn)
	}

	stats := relay.Run(
		s.conn, dcConn,
		clientRead, clientWrite,
		relay.WithBufSize(s.bufSize),
	)

	fromClient := stats.BytesFromClient.Load()
	fromDC := stats.BytesFromDC.Load()
	s.metrics.BytesFromClients.Add(float64(fromClient))
	s.metrics.BytesFromDCs.Add(float64(fromDC))
	log.Debug("session closed", "bytes_up", fromClient, "bytes_down", fromDC)
}

// handshake reads the client's init frame, validates the secret, and returns
// a ready-to-use obfuscated2 cipher.
func (s *session) handshake(log *slog.Logger) (*obfs.Cipher, error) {
	var nonce []byte

	if s.sec.Type == secret.TypeFakeTLS {
		var err error
		nonce, err = faketls.Handshake(s.conn, s.sec.Key, s.sec.Domain)
		if err != nil {
			return nil, err
		}
	} else {
		// Plain obfuscated2: client sends 64-byte nonce directly.
		nonce = make([]byte, 64)
		if _, err := io.ReadFull(s.conn, nonce); err != nil {
			return nil, fmt.Errorf("read nonce: %w", err)
		}
	}

	return obfs.New(nonce, s.sec.Key)
}

func errReason(err error) string {
	if err == nil {
		return "none"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "SNI"):
		return "sni_mismatch"
	case strings.Contains(msg, "HMAC") || strings.Contains(msg, "digest"):
		return "bad_digest"
	case strings.Contains(msg, "timestamp"):
		return "timestamp"
	case strings.Contains(msg, "protocol magic"):
		return "bad_magic"
	case strings.Contains(msg, "DC"):
		return "bad_dc"
	case strings.Contains(msg, "EOF") || strings.Contains(msg, "reset") || strings.Contains(msg, "broken pipe"):
		return "connection_closed"
	default:
		return "other"
	}
}
