package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/guvchick/mtproto-proxy/internal/config"
	"github.com/guvchick/mtproto-proxy/internal/dc"
	"github.com/guvchick/mtproto-proxy/internal/faketls"
	"github.com/guvchick/mtproto-proxy/internal/obfs"
	"github.com/guvchick/mtproto-proxy/internal/relay"
	"github.com/guvchick/mtproto-proxy/internal/secret"
	"github.com/guvchick/mtproto-proxy/internal/telemetry"
)

type session struct {
	conn     net.Conn
	sec      *secret.Secret
	family   dc.AddrFamily
	upstream *config.UpstreamConfig
	tlsOpts  faketls.Options
	metrics  *telemetry.Metrics
	log      *slog.Logger
	bufSize  int
}

func (s *session) handle() {
	defer s.conn.Close()

	log := s.log.With("client", s.conn.RemoteAddr().String())
	s.metrics.TotalConnections.Inc()
	s.metrics.ActiveConnections.Inc()
	defer s.metrics.ActiveConnections.Dec()

	// Read the 64-byte obfuscated2 nonce (strips fake-TLS layer if needed).
	nonce, err := s.readNonce()
	if err != nil {
		log.Debug("handshake failed", "err", err)
		s.metrics.RejectedConnections.Inc()
		s.metrics.HandshakeErrors.WithLabelValues(errReason(err)).Inc()
		return
	}

	if s.upstream != nil {
		s.relayToUpstream(nonce, log)
	} else {
		s.relayToDC(nonce, log)
	}
}

// readNonce returns the raw 64-byte obfuscated2 nonce.
// For fake-TLS secrets it first completes the TLS masquerade.
func (s *session) readNonce() ([]byte, error) {
	if s.sec.Type == secret.TypeFakeTLS {
		return faketls.Handshake(s.conn, s.sec.Key, s.sec.Domain, s.tlsOpts)
	}
	nonce := make([]byte, 64)
	if _, err := io.ReadFull(s.conn, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	return nonce, nil
}

// relayToDC decrypts the nonce, connects to the Telegram DC, and relays data.
func (s *session) relayToDC(nonce []byte, log *slog.Logger) {
	cipher, err := obfs.New(nonce, s.sec.Key)
	if err != nil {
		log.Debug("obfs handshake failed", "err", err)
		s.metrics.RejectedConnections.Inc()
		s.metrics.HandshakeErrors.WithLabelValues(errReason(err)).Inc()
		return
	}

	log = log.With("dc", cipher.DC, "proto", cipher.Protocol)
	log.Debug("connected to DC")
	s.metrics.ConnectionsByDC.WithLabelValues(fmt.Sprintf("%d", cipher.DC)).Inc()

	dcConn, err := dc.Dial(cipher.DC, s.family)
	if err != nil {
		log.Warn("dial DC failed", "err", err)
		s.metrics.RejectedConnections.Inc()
		return
	}
	defer dcConn.Close()

	if _, err := dcConn.Write(cipher.InitTag()); err != nil {
		log.Warn("write init tag failed", "err", err)
		return
	}

	var clientRead io.Reader
	var clientWrite io.Writer
	if s.sec.Type == secret.TypeFakeTLS {
		clientRead = cipher.NewReader(faketls.NewRecordReader(s.conn))
		clientWrite = cipher.NewWriter(faketls.NewRecordWriter(s.conn))
	} else {
		clientRead = cipher.NewReader(s.conn)
		clientWrite = cipher.NewWriter(s.conn)
	}

	stats := relay.Run(s.conn, dcConn, clientRead, clientWrite,
		relay.WithBufSize(s.bufSize))
	s.metrics.BytesFromClients.Add(float64(stats.BytesFromClient.Load()))
	s.metrics.BytesFromDCs.Add(float64(stats.BytesFromDC.Load()))
	log.Debug("session closed",
		"up", stats.BytesFromClient.Load(),
		"down", stats.BytesFromDC.Load())
}

// relayToUpstream forwards the raw obfuscated2 stream to another proxy server.
// The front proxy only handles the fake-TLS masquerade layer; the upstream
// does the full obfuscated2 decode and DC connection.
//
// Data flow:
//
//	client ←[TLS records]→ front proxy ←[raw TCP]→ upstream → Telegram DC
func (s *session) relayToUpstream(nonce []byte, log *slog.Logger) {
	upConn, err := net.Dial("tcp", s.upstream.Addr())
	if err != nil {
		log.Warn("dial upstream failed", "addr", s.upstream.Addr(), "err", err)
		s.metrics.RejectedConnections.Inc()
		return
	}
	defer upConn.Close()

	// Send the raw obfuscated2 nonce to the upstream proxy first.
	if _, err := upConn.Write(nonce); err != nil {
		log.Warn("send nonce to upstream failed", "err", err)
		return
	}

	log.Debug("relaying to upstream", "upstream", s.upstream.Addr())

	// Client side: strip/wrap TLS records for fake-TLS secrets.
	// Upstream side: raw TCP (upstream handles obfuscated2 itself).
	var clientRead io.Reader
	var clientWrite io.Writer
	if s.sec.Type == secret.TypeFakeTLS {
		clientRead = faketls.NewRecordReader(s.conn)
		clientWrite = faketls.NewRecordWriter(s.conn)
	} else {
		clientRead = s.conn
		clientWrite = s.conn
	}

	stats := relay.Run(s.conn, upConn, clientRead, clientWrite,
		relay.WithBufSize(s.bufSize))
	s.metrics.BytesFromClients.Add(float64(stats.BytesFromClient.Load()))
	s.metrics.BytesFromDCs.Add(float64(stats.BytesFromDC.Load()))
	log.Debug("upstream session closed",
		"up", stats.BytesFromClient.Load(),
		"down", stats.BytesFromDC.Load())
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
