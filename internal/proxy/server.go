// Package proxy wires the listener, per-connection sessions, and telemetry.
package proxy

import (
	"context"
	"log/slog"
	"net"

	"github.com/guvchick/mtproto-proxy/internal/config"
	"github.com/guvchick/mtproto-proxy/internal/dc"
	"github.com/guvchick/mtproto-proxy/internal/secret"
	"github.com/guvchick/mtproto-proxy/internal/telemetry"
)

// Server is the main MTProto proxy listener.
type Server struct {
	cfg     *config.Config
	sec     *secret.Secret
	family  dc.AddrFamily
	metrics *telemetry.Metrics
	log     *slog.Logger
}

// New builds a Server from configuration.
func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	sec, err := secret.Parse(cfg.Secret)
	if err != nil {
		return nil, err
	}

	family, err := dc.ParseFamily(cfg.AddrFamily)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:     cfg,
		sec:     sec,
		family:  family,
		metrics: telemetry.New(),
		log:     log,
	}, nil
}

// ListenAndServe starts the proxy and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.log.Info("proxy listening",
		"addr", s.cfg.Listen,
		"secret_type", secretTypeName(s.sec.Type),
		"domain", s.sec.Domain,
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.log.Warn("accept error", "err", err)
				continue
			}
		}
		go s.newSession(conn).handle()
	}
}

// Metrics returns the server's metrics registry (for testing / introspection).
func (s *Server) Metrics() *telemetry.Metrics { return s.metrics }

func (s *Server) newSession(conn net.Conn) *session {
	return &session{
		conn:    conn,
		sec:     s.sec,
		family:  s.family,
		metrics: s.metrics,
		log:     s.log,
		bufSize: max(s.cfg.ReadBufSize, 4096),
	}
}

func secretTypeName(t secret.Type) string {
	switch t {
	case secret.TypeFakeTLS:
		return "fake-tls"
	case secret.TypePadded:
		return "padded"
	default:
		return "simple"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
