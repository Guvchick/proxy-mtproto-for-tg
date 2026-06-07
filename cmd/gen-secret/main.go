// gen-secret generates MTProto proxy secrets and prints ready-to-use tg:// links.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/guvchick/mtproto-proxy/internal/secret"
)

func main() {
	var (
		fakeTLS = flag.Bool("faketls", false, "generate a fake-TLS (ee) secret")
		domain  = flag.String("domain", "www.google.com", "domain for fake-TLS SNI masquerade")
		host    = flag.String("host", "YOUR_SERVER_IP", "proxy server IP or hostname")
		port    = flag.Int("port", 443, "proxy listen port")
	)
	flag.Parse()

	raw, err := secret.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var sec string
	var linkSecret string

	if *fakeTLS {
		sec = secret.FakeTLSString(raw, *domain)
		linkSecret = sec
		fmt.Println("Secret type : fake-TLS (ee)")
		fmt.Println("Domain      :", *domain)
	} else {
		sec = raw
		linkSecret = "dd" + raw // use padded variant for better compatibility
		fmt.Println("Secret type : simple")
	}

	fmt.Println("Secret      :", sec)
	fmt.Println()
	fmt.Printf("tg://proxy?server=%s&port=%d&secret=%s\n", *host, *port, linkSecret)
	fmt.Println()
	fmt.Println("Add to config.yaml:")
	fmt.Printf("  secret: %q\n", sec)

	// Also print raw key bytes for reference.
	keyBytes, _ := hex.DecodeString(raw)
	fmt.Printf("\nRaw key (hex): %x\n", keyBytes)
}
