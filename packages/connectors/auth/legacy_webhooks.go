package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// LegacyDelivery preserves the existing product's durable privacy processor
// while the app's webhook receiver moves centrally. It contains no tokens.
type LegacyDelivery struct {
	URL          string    `json:"url"`
	Shop         string    `json:"shop"`
	WebhookID    string    `json:"webhook_id"`
	Acknowledged bool      `json:"acknowledged"`
	Attempts     uint32    `json:"attempts"`
	LeaseUntil   time.Time `json:"lease_until"`
	NextAttempt  time.Time `json:"next_attempt"`
}

// ConfigureLegacyShopifyWebhooks is startup-only operator configuration, never
// a caller-controlled destination. Configure all lifecycle/privacy topics.
func (s *Server) ConfigureLegacyShopifyWebhooks(routes map[string]string) error {
	if len(routes) == 0 {
		return nil
	}
	if s.QAEnrollmentEnabled() || s.shopifyQA != nil || len(routes) != 4 || s.Providers["shopify"].ID == "" {
		return ErrDenied
	}
	reviewed := map[string]string{}
	for _, topic := range []string{"app/uninstalled", "customers/data_request", "customers/redact", "shop/redact"} {
		u, err := url.Parse(routes[topic])
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path == "" ||
			(u.Scheme != "https" && !(s.Engine.AllowLoopback && u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))) {
			return ErrDenied
		}
		reviewed[topic] = u.String()
	}
	s.legacyShopifyWebhooks = reviewed
	return nil
}

func (s *Server) RunLegacyShopifyDeliveries(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		s.DeliverLegacyShopifyWebhooks(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// DeliverLegacyShopifyWebhooks performs bounded, durable at-least-once delivery.
// The product's normal webhook-ID deduplication handles a lost HTTP response.
func (s *Server) DeliverLegacyShopifyWebhooks(ctx context.Context) {
	snapshot := s.Store.snapshot()
	ids := []string{}
	for id, event := range snapshot.Events {
		if event.Legacy != nil && !event.Legacy.Acknowledged && !s.now().Before(event.Legacy.NextAttempt) && !s.now().Before(event.Legacy.LeaseUntil) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > 50 {
		ids = ids[:50]
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, id := range ids {
		if ctx.Err() != nil {
			return
		}
		var event *Event
		err := s.Store.update(func(state *State) error {
			candidate := state.Events[id]
			if candidate == nil || candidate.Legacy == nil || candidate.Legacy.Acknowledged || s.now().Before(candidate.Legacy.NextAttempt) || s.now().Before(candidate.Legacy.LeaseUntil) {
				return ErrConflict
			}
			candidate.Legacy.LeaseUntil = s.now().Add(25 * time.Second)
			candidate.Legacy.Attempts++
			event = candidate
			return nil
		})
		if err != nil {
			continue
		}
		body, err := s.decryptEvent(event)
		accepted := false
		if err == nil {
			secret, readErr := os.ReadFile(s.Providers["shopify"].SecretFile)
			if readErr == nil {
				deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
				req, requestErr := http.NewRequestWithContext(deadline, "POST", event.Legacy.URL, bytes.NewReader(body))
				if requestErr == nil {
					mac := hmac.New(sha256.New, []byte(strings.TrimSpace(string(secret))))
					mac.Write(body)
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("X-Shopify-Hmac-Sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
					req.Header.Set("X-Shopify-Topic", event.Topic)
					req.Header.Set("X-Shopify-Shop-Domain", event.Legacy.Shop)
					req.Header.Set("X-Shopify-Webhook-Id", event.Legacy.WebhookID)
					req.Header.Set("X-Shopify-Triggered-At", event.OccurredAt.Format(time.RFC3339Nano))
					res, sendErr := client.Do(req)
					if sendErr == nil {
						accepted = res.StatusCode >= 200 && res.StatusCode < 300
						io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
						res.Body.Close()
					}
				}
				cancel()
			}
		}
		_ = s.Store.update(func(state *State) error {
			current := state.Events[id]
			if current == nil || current.Legacy == nil {
				return ErrDenied
			}
			current.Legacy.LeaseUntil = time.Time{}
			current.Legacy.Acknowledged = accepted
			attempt := current.Legacy.Attempts
			if attempt > 8 {
				attempt = 8
			}
			current.Legacy.NextAttempt = s.now().Add(time.Second * time.Duration(1<<attempt))
			all := accepted
			for _, ack := range current.Acknowledged {
				all = all && ack
			}
			if all {
				current.Ciphertext = ""
				current.Nonce = ""
			}
			return nil
		})
	}
}
