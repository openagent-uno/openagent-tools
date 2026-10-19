package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	legacyRelayVersion   = "X-OpenAgent-Relay-Version"
	legacyRelayTime      = "X-OpenAgent-Relay-Delivered-At"
	legacyRelayAudience  = "X-OpenAgent-Relay-Audience"
	legacyRelaySignature = "X-OpenAgent-Relay-Signature"
)

// SignLegacyShopifyDelivery authenticates transport freshness independently of
// Shopify's original occurrence time. Retries must retain the original body,
// webhook ID and occurrence time; only this delivery timestamp is refreshed.
func SignLegacyShopifyDelivery(request *http.Request, body, secret []byte, deliveredAt time.Time) error {
	if request == nil || request.URL == nil || request.Header == nil || !validLegacyRelayAudience(request.URL.String()) {
		return ErrDenied
	}
	request.Header.Set(legacyRelayVersion, "1")
	request.Header.Set(legacyRelayTime, deliveredAt.UTC().Format(time.RFC3339Nano))
	request.Header.Set(legacyRelayAudience, request.URL.String())
	message, err := legacyRelayMessage(request, body, secret)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	request.Header.Set(legacyRelaySignature, base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return nil
}

// VerifyLegacyShopifyDelivery returns false,nil for a direct provider request.
// Any partially present or invalid relay envelope fails closed. The audience is
// the receiver's operator-configured public endpoint, never a forwarded header.
// This does not replace verification of Shopify's body HMAC or durable dedup.
func VerifyLegacyShopifyDelivery(request *http.Request, body, secret []byte, audience string, now time.Time) (bool, error) {
	if request == nil {
		return false, ErrDenied
	}
	present := false
	for _, header := range []string{legacyRelayVersion, legacyRelayTime, legacyRelayAudience, legacyRelaySignature} {
		present = present || len(request.Header.Values(header)) != 0
	}
	if !present {
		return false, nil
	}
	if !validLegacyRelayAudience(audience) || request.Header.Get(legacyRelayAudience) != audience ||
		len(request.Header.Values(legacyRelaySignature)) != 1 || len(request.Header.Get(legacyRelaySignature)) > 128 || strings.ContainsAny(request.Header.Get(legacyRelaySignature), "\r\n\x00") {
		return false, ErrDenied
	}
	stamp, err := time.Parse(time.RFC3339Nano, request.Header.Get(legacyRelayTime))
	if err != nil || stamp.Before(now.Add(-2*time.Minute)) || stamp.After(now.Add(time.Minute)) {
		return false, ErrDenied
	}
	message, err := legacyRelayMessage(request, body, secret)
	if err != nil {
		return false, err
	}
	provided, err := base64.StdEncoding.DecodeString(request.Header.Get(legacyRelaySignature))
	if err != nil || len(provided) != sha256.Size {
		return false, ErrDenied
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	if !hmac.Equal(mac.Sum(nil), provided) {
		return false, ErrDenied
	}
	return true, nil
}

func validLegacyRelayAudience(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Host != "" && u.User == nil && u.Path != "" && u.RawQuery == "" && u.Fragment == "" &&
		(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"))
}

func legacyRelayMessage(request *http.Request, body, secret []byte) ([]byte, error) {
	if request.Method != http.MethodPost || len(secret) < 16 || len(secret) > 65536 || len(body) > 1<<20 ||
		request.Header.Get(legacyRelayVersion) != "1" || !validLegacyRelayAudience(request.Header.Get(legacyRelayAudience)) {
		return nil, ErrDenied
	}
	fields := []string{"openagent-shopify-legacy-relay/v1", request.Header.Get(legacyRelayAudience)}
	for _, header := range []string{legacyRelayTime, "X-Shopify-Topic", "X-Shopify-Shop-Domain", "X-Shopify-Webhook-Id", "X-Shopify-Api-Version", "X-Shopify-Triggered-At"} {
		values := request.Header.Values(header)
		if len(values) != 1 || values[0] == "" || len(values[0]) > 2048 || strings.ContainsAny(values[0], "\r\n\x00") || strings.TrimSpace(values[0]) != values[0] {
			return nil, ErrDenied
		}
		fields = append(fields, values[0])
	}
	if len(request.Header.Values(legacyRelayVersion)) != 1 || len(request.Header.Values(legacyRelayAudience)) != 1 {
		return nil, ErrDenied
	}
	hash := sha256.Sum256(body)
	fields = append(fields, hex.EncodeToString(hash[:]))
	return []byte(strings.Join(fields, "\n")), nil
}
