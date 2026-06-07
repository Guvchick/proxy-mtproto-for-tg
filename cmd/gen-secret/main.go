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
		// Empty domain = self-SNI mode: Telegram client will use whatever SNI
		// you configure, typically your server's own domain.
		// Use a Russian domain (e.g. max.ru, vk.com) to avoid RU DPI blocks.
		domain = flag.String("domain", "", "SNI domain for fake-TLS masquerade (empty = accept any / self-SNI)")
		host   = flag.String("host", "YOUR_SERVER_IP", "proxy server IP or hostname")
		port   = flag.Int("port", 443, "proxy listen port")
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
		if *domain == "" {
			fmt.Println("Secret type : fake-TLS (ee) — self-SNI / any domain")
		} else {
			fmt.Println("Secret type : fake-TLS (ee)")
			fmt.Println("Domain      :", *domain)
		}
	} else {
		sec = raw
		linkSecret = "dd" + raw
		fmt.Println("Secret type : padded obfuscated2 (dd)")
	}

	fmt.Println("Secret      :", sec)
	fmt.Println()
	fmt.Printf("tg://proxy?server=%s&port=%d&secret=%s\n", *host, *port, linkSecret)
	fmt.Println()
	fmt.Println("Paste into config.yaml:")
	fmt.Printf("  secret: %q\n", sec)

	if *fakeTLS && *domain != "" {
		fmt.Println()
		fmt.Println("NOTE: set the same domain in config.yaml as fake_tls_domain")
		fmt.Printf("  (or leave empty to accept any SNI)\n")
	}

	keyBytes, _ := hex.DecodeString(raw)
	fmt.Printf("\nRaw key bytes (hex): %x\n", keyBytes)
}
