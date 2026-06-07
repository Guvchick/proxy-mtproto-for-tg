// Package relay provides a bidirectional byte-stream relay between two
// net.Conn objects.  Each direction runs in its own goroutine; both are torn
// down when either side closes.
package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Stats accumulates byte counts for a relay session.
type Stats struct {
	BytesFromClient atomic.Int64
	BytesFromDC     atomic.Int64
}

// Option configures the relay.
type Option func(*relay)

type relay struct {
	clientConn net.Conn
	dcConn     net.Conn
	clientRead io.Reader
	clientWrite io.Writer
	dcRead     io.Reader
	dcWrite    io.Writer
	bufSize    int
	stats      *Stats
	idleTimeout time.Duration
}

// WithStats collects byte statistics.
func WithStats(s *Stats) Option { return func(r *relay) { r.stats = s } }

// WithBufSize sets the copy buffer size (default 32 KiB).
func WithBufSize(n int) Option { return func(r *relay) { r.bufSize = n } }

// WithIdleTimeout closes the relay if no data flows within d.
func WithIdleTimeout(d time.Duration) Option { return func(r *relay) { r.idleTimeout = d } }

// Run relays data between the two connections until one closes.
//
// clientRead  / clientWrite — possibly cipher-wrapped streams for the client side.
// dcRead      / dcWrite     — plain streams for the DC side (already init-tagged).
func Run(
	clientConn net.Conn,
	dcConn net.Conn,
	clientRead io.Reader,
	clientWrite io.Writer,
	opts ...Option,
) *Stats {
	r := &relay{
		clientConn:  clientConn,
		dcConn:      dcConn,
		clientRead:  clientRead,
		clientWrite: clientWrite,
		dcRead:      dcConn,
		dcWrite:     dcConn,
		bufSize:     32 * 1024,
		stats:       &Stats{},
	}
	for _, o := range opts {
		o(r)
	}
	r.run()
	return r.stats
}

func (r *relay) run() {
	var wg sync.WaitGroup
	wg.Add(2)

	done := make(chan struct{})
	close := func() {
		r.clientConn.Close()
		r.dcConn.Close()
	}

	// client → DC
	go func() {
		defer wg.Done()
		defer close()
		r.copy(r.dcConn, r.clientRead, &r.stats.BytesFromClient)
		select {
		case <-done:
		default:
		}
	}()

	// DC → client
	go func() {
		defer wg.Done()
		defer close()
		r.copy(r.clientWrite, r.dcRead, &r.stats.BytesFromDC)
		select {
		case <-done:
		default:
		}
	}()

	wg.Wait()
}

func (r *relay) copy(dst io.Writer, src io.Reader, counter *atomic.Int64) {
	buf := make([]byte, r.bufSize)
	for {
		if r.idleTimeout > 0 {
			if nc, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
				_ = nc.SetReadDeadline(time.Now().Add(r.idleTimeout))
			}
		}
		n, err := src.Read(buf)
		if n > 0 {
			if r.idleTimeout > 0 {
				if nc, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
					_ = nc.SetWriteDeadline(time.Now().Add(r.idleTimeout))
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			counter.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}
