package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// ShopifyEvent is the minimal authenticated lifecycle/privacy data consumed by hosts.
type ShopifyEvent struct {
	Shop          string
	ShopID        string
	CustomerID    string
	CustomerEmail string
	OrderIDs      []string
	DataRequestID string
	BodySHA256    string
}

func numericID(value any) string {
	switch v := value.(type) {
	case json.Number:
		if n, err := strconv.ParseUint(v.String(), 10, 64); err == nil && n > 0 {
			return v.String()
		}
	case string:
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			return v
		}
	}
	return ""
}
func DecodeShopifyEvent(topic string, body []byte) (ShopifyEvent, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil {
		return ShopifyEvent{}, ErrAuthentication
	}
	shop, _ := value["shop_domain"].(string)
	if !ValidShop(shop) {
		return ShopifyEvent{}, ErrAuthentication
	}
	hash := sha256.Sum256(body)
	event := ShopifyEvent{Shop: shop, ShopID: numericID(value["shop_id"]), OrderIDs: []string{}, BodySHA256: hex.EncodeToString(hash[:])}
	if event.ShopID == "" {
		event.ShopID = numericID(value["id"])
	}
	if topic == "app/uninstalled" {
		return event, nil
	}
	if topic != "customers/data_request" && topic != "customers/redact" && topic != "shop/redact" || event.ShopID == "" {
		return ShopifyEvent{}, ErrAuthentication
	}
	if customer, ok := value["customer"].(map[string]any); ok {
		event.CustomerID = numericID(customer["id"])
		event.CustomerEmail, _ = customer["email"].(string)
	}
	if request, ok := value["data_request"].(map[string]any); ok {
		event.DataRequestID = numericID(request["id"])
	}
	key := "orders_to_redact"
	if topic == "customers/data_request" {
		key = "orders_requested"
	}
	if orders, ok := value[key].([]any); ok {
		if len(orders) > 10000 {
			return ShopifyEvent{}, ErrAuthentication
		}
		for _, order := range orders {
			id := numericID(order)
			if id == "" {
				return ShopifyEvent{}, ErrAuthentication
			}
			event.OrderIDs = append(event.OrderIDs, id)
		}
	}
	return event, nil
}
