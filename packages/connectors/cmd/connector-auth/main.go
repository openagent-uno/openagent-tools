package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/auth"
	"github.com/openagent-uno/openagent-tools/packages/connectors/oauth"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8094", "HTTP listener behind a TLS ingress")
	origin := flag.String("origin", "https://auth.openagent.uno", "Public HTTPS origin")
	statePath := flag.String("state", "", "Single-writer durable metadata path")
	providersPath := flag.String("providers", "", "Reviewed provider configuration JSON")
	keyPath := flag.String("event-key", "", "File containing a 32-byte hex encryption key for webhook storage")
	legacyPath := flag.String("legacy-shopify-webhooks", "", "Reviewed topic-to-HTTPS-product webhook routes for existing installations")
	qaPath := flag.String("qa-enrollment", "", "Startup-only installation/store allowlist; public readiness remains disabled")
	shopifyQAPath := flag.String("shopify-qa-enrollment", "", "Startup-only Shopify installation/store allowlist; other providers remain public")
	flag.Parse()
	if *statePath == "" || *providersPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "state, providers and event-key are required")
		os.Exit(1)
	}
	data, err := os.ReadFile(*providersPath)
	if err != nil {
		fatal()
	}
	var providers []oauth.Provider
	if json.Unmarshal(data, &providers) != nil {
		fatal()
	}
	keyData, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal()
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyData)))
	if err != nil || len(key) != 32 {
		fatal()
	}
	store, err := auth.NewStore(*statePath)
	if err != nil {
		fatal()
	}
	handler, err := auth.NewServer(store, oauth.Engine{}, providers, *origin, key)
	if err != nil {
		fatal()
	}
	if *legacyPath != "" {
		data, err := os.ReadFile(*legacyPath)
		var routes map[string]string
		if err != nil || json.Unmarshal(data, &routes) != nil || handler.ConfigureLegacyShopifyWebhooks(routes) != nil {
			fatal()
		}
	}
	if *qaPath != "" {
		data, err := os.ReadFile(*qaPath)
		var config auth.QAEnrollment
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || handler.ConfigureQAEnrollment(config) != nil {
			fatal()
		}
	}
	if *shopifyQAPath != "" {
		data, err := os.ReadFile(*shopifyQAPath)
		var config auth.QAEnrollment
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || handler.ConfigureShopifyQAEnrollment(config) != nil {
			fatal()
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if len(handler.Providers) == 0 || handler.QAEnrollmentEnabled() {
			http.Error(w, "provider activation pending", 503)
			return
		}
		w.WriteHeader(200)
	})
	mux.Handle("/", handler)
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go handler.RunLegacyShopifyDeliveries(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal()
	}
}
func fatal() {
	fmt.Fprintln(os.Stderr, "connector authentication service configuration or startup failed")
	os.Exit(1)
}
