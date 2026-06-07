// Package telemetry exposes Prometheus metrics and structured logging helpers.
package telemetry

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus counters / gauges for the proxy.
type Metrics struct {
	ActiveConnections  prometheus.Gauge
	TotalConnections   prometheus.Counter
	RejectedConnections prometheus.Counter
	BytesFromClients   prometheus.Counter
	BytesFromDCs       prometheus.Counter
	HandshakeErrors    *prometheus.CounterVec // label: reason
	ConnectionsByDC    *prometheus.CounterVec // label: dc
}

// New registers and returns all metrics under the "mtproxy" namespace.
func New() *Metrics {
	return &Metrics{
		ActiveConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "mtproxy",
			Name:      "active_connections",
			Help:      "Number of currently active proxy connections.",
		}),
		TotalConnections: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "mtproxy",
			Name:      "total_connections_total",
			Help:      "Total number of accepted connections.",
		}),
		RejectedConnections: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "mtproxy",
			Name:      "rejected_connections_total",
			Help:      "Total number of rejected / failed connections.",
		}),
		BytesFromClients: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "mtproxy",
			Name:      "bytes_from_clients_total",
			Help:      "Total bytes received from Telegram clients.",
		}),
		BytesFromDCs: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "mtproxy",
			Name:      "bytes_from_dcs_total",
			Help:      "Total bytes received from Telegram DCs.",
		}),
		HandshakeErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mtproxy",
			Name:      "handshake_errors_total",
			Help:      "Total handshake errors, labelled by reason.",
		}, []string{"reason"}),
		ConnectionsByDC: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "mtproxy",
			Name:      "connections_by_dc_total",
			Help:      "Total connections per Telegram DC.",
		}, []string{"dc"}),
	}
}

// ServeMetrics starts the Prometheus HTTP endpoint in a background goroutine.
func ServeMetrics(addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	go func() {
		log.Info("metrics server listening", "addr", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error("metrics server error", "err", err)
		}
	}()
}

// NewLogger creates a slog.Logger based on the config level and format.
func NewLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.ToLower(format) == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}
