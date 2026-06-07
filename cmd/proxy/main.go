package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/guvchick/mtproto-proxy/internal/config"
	"github.com/guvchick/mtproto-proxy/internal/proxy"
	"github.com/guvchick/mtproto-proxy/internal/telemetry"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log := telemetry.NewLogger(cfg.Log.Level, cfg.Log.Format)

	if cfg.Metrics.Enabled {
		telemetry.ServeMetrics(cfg.Metrics.Listen, log)
	}

	srv, err := proxy.New(cfg, log)
	if err != nil {
		log.Error("init failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
	log.Info("proxy stopped")
}
