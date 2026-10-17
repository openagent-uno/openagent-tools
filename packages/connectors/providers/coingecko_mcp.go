package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// SDK/MCP v8.1.0 source 9eed2c82d7b039f0b44d3e50c76d0dea24ff3890:
// coingecko/coingecko-typescript src/resources/{simple/price,global/global}.ts,
// packages/mcp-server/src/{code-tool,remote-sandbox-handler,types}.ts.
// This pins a reviewed source contract, not deployed-byte identity or actual
// free-service operation acceptance. Callers never supply or select SDK code.
const coinGeckoIDPattern = `^[a-z0-9]+(-[a-z0-9]+)*$`
const coinGeckoMaxResponse = 256 << 10

var coinGeckoID = regexp.MustCompile(coinGeckoIDPattern)

// Market-share keys are provider tickers, not request coin identifiers. The
// observed global response includes figr_heloc; keep underscores output-only.
var coinGeckoTicker = regexp.MustCompile(`^[a-z0-9]+([-_][a-z0-9]+)*$`)

func coinGeckoList(value any, currencies bool) bool {
	list, ok := value.([]any)
	maximum := 10
	if currencies {
		maximum = 3
	}
	if !ok || len(list) < 1 || len(list) > maximum {
		return false
	}
	seen := map[string]bool{}
	for _, value := range list {
		text, ok := value.(string)
		if !ok || seen[text] {
			return false
		}
		if currencies {
			if text != "usd" && text != "eur" && text != "gbp" {
				return false
			}
		} else if len(text) < 1 || len(text) > 64 || !coinGeckoID.MatchString(text) {
			return false
		}
		seen[text] = true
	}
	return true
}

func compileCoinGeckoArguments(operation string, args map[string]any) (map[string]any, error) {
	var code string
	switch operation {
	case "files.coingecko.price":
		if len(args) != 2 || !coinGeckoList(args["ids"], false) || !coinGeckoList(args["currencies"], true) {
			return nil, domain.ErrInvalidArguments
		}
		join := func(value any) string {
			var stringsList []string
			for _, entry := range value.([]any) {
				stringsList = append(stringsList, entry.(string))
			}
			return strings.Join(stringsList, ",")
		}
		query, err := json.Marshal(map[string]any{"ids": join(args["ids"]), "vs_currencies": join(args["currencies"]), "include_last_updated_at": true})
		if err != nil {
			return nil, domain.ErrInvalidArguments
		}
		code = `async function run(client) { return {schema:"openagent-coingecko-prices-v1",data:await client.simple.price.get(` + string(query) + `,{maxRetries:0,timeout:10000})}; }`
	case "files.coingecko.global":
		if len(args) != 0 {
			return nil, domain.ErrInvalidArguments
		}
		code = `async function run(client) { return {schema:"openagent-coingecko-global-v1",data:await client.global.get({maxRetries:0,timeout:10000})}; }`
	default:
		return nil, domain.ErrDenied
	}
	return map[string]any{"code": code}, nil
}

// Bounded token parsing rejects duplicates before Go maps can erase them. The
// same parser guards the JSON-RPC envelope and the nested text JSON separately.
func decodeCoinGeckoJSON(raw []byte) (any, error) {
	invalid := errors.New("invalid CoinGecko JSON")
	if len(raw) == 0 || len(raw) > coinGeckoMaxResponse || !utf8.Valid(raw) {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	budget := 10000
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		budget--
		if depth > 16 || budget < 0 {
			return nil, invalid
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, invalid
		}
		delimiter, nested := token.(json.Delim)
		if !nested {
			if number, ok := token.(json.Number); ok {
				value, err := number.Float64()
				if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
					return nil, invalid
				}
			}
			return token, nil
		}
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, invalid
				}
				key, ok := keyToken.(string)
				if !ok || len(key) > 2048 || len(object) >= 1024 {
					return nil, invalid
				}
				if _, exists := object[key]; exists {
					return nil, invalid
				}
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, invalid
			}
			return object, nil
		case '[':
			array := []any{}
			for decoder.More() {
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, invalid
			}
			return array, nil
		default:
			return nil, invalid
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid
	}
	return value, nil
}

func validateCoinGeckoMCPBody(body, raw []byte, contentType string) error {
	if strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
		// This fixed subset expects one response, never a stream of executable
		// results or a later success hiding an earlier error response.
		count := 0
		for _, line := range bytes.Split(body, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			candidate := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if bytes.Equal(candidate, []byte("[DONE]")) {
				continue
			}
			count++
			if _, err := decodeCoinGeckoJSON(candidate); err != nil {
				return err
			}
		}
		if count != 1 {
			return errors.New("invalid CoinGecko response stream")
		}
	}
	_, err := decodeCoinGeckoJSON(raw)
	return err
}

func decodeCoinGeckoResult(result map[string]any, operation string, args map[string]any) (map[string]any, error) {
	invalid := errors.New("invalid CoinGecko operation output")
	for key, value := range result {
		if key != "content" && (key != "isError" || value != false) {
			return nil, invalid
		}
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		return nil, invalid
	}
	entry, ok := content[0].(map[string]any)
	if !ok || len(entry) != 2 || entry["type"] != "text" {
		return nil, invalid
	}
	text, ok := entry["text"].(string)
	if !ok {
		return nil, invalid
	}
	value, err := decodeCoinGeckoJSON([]byte(text))
	if err != nil {
		return nil, invalid
	}
	payload, ok := value.(map[string]any)
	if !ok {
		return nil, invalid
	}
	if wrapped, present := payload["result"]; present {
		for key, value := range payload {
			if key == "result" {
				continue
			}
			lines, ok := value.([]any)
			if (key != "log_lines" && key != "err_lines") || !ok || len(lines) != 0 {
				return nil, invalid
			}
		}
		payload, ok = wrapped.(map[string]any)
		if !ok {
			return nil, invalid
		}
	}
	if len(payload) != 2 {
		return nil, invalid
	}
	data, ok := payload["data"].(map[string]any)
	if !ok {
		return nil, invalid
	}
	switch operation {
	case "files.coingecko.price":
		if payload["schema"] != "openagent-coingecko-prices-v1" || !validCoinGeckoPrices(data, args) {
			return nil, invalid
		}
	case "files.coingecko.global":
		if payload["schema"] != "openagent-coingecko-global-v1" || !validCoinGeckoGlobal(data) {
			return nil, invalid
		}
	default:
		return nil, invalid
	}
	return payload, nil
}

func coinGeckoNumber(value any, nonnegative, integer bool) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Float64()
	if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) || (nonnegative && parsed < 0) {
		return false
	}
	return !integer || (parsed <= 9007199254740991 && math.Trunc(parsed) == parsed)
}

func validCoinGeckoPrices(data map[string]any, args map[string]any) bool {
	if !coinGeckoList(args["ids"], false) || !coinGeckoList(args["currencies"], true) {
		return false
	}
	ids, currencies := args["ids"].([]any), args["currencies"].([]any)
	if len(data) != len(ids) {
		return false
	}
	for _, id := range ids {
		prices, ok := data[id.(string)].(map[string]any)
		if !ok || len(prices) != len(currencies)+1 || !coinGeckoNumber(prices["last_updated_at"], true, true) {
			return false
		}
		for _, currency := range currencies {
			if !coinGeckoNumber(prices[currency.(string)], true, false) {
				return false
			}
		}
	}
	return true
}

func validCoinGeckoGlobal(response map[string]any) bool {
	if len(response) != 1 {
		return false
	}
	data, ok := response["data"].(map[string]any)
	if !ok {
		return false
	}
	counts := []string{"active_cryptocurrencies", "ended_icos", "markets", "ongoing_icos", "upcoming_icos"}
	maps := []string{"total_market_cap", "total_volume", "market_cap_percentage"}
	allowed := map[string]bool{"updated_at": true, "market_cap_change_percentage_24h_usd": true, "volume_change_percentage_24h_usd": true}
	for _, field := range counts {
		allowed[field] = true
		if !coinGeckoNumber(data[field], true, true) {
			return false
		}
	}
	for _, field := range maps {
		allowed[field] = true
		values, ok := data[field].(map[string]any)
		if !ok || len(values) == 0 || len(values) > 1024 {
			return false
		}
		for key, value := range values {
			validKey := coinGeckoID.MatchString(key)
			if field == "market_cap_percentage" {
				validKey = coinGeckoTicker.MatchString(key)
			}
			if len(key) > 64 || !validKey || !coinGeckoNumber(value, true, false) {
				return false
			}
		}
	}
	for field, value := range data {
		if !allowed[field] {
			return false
		}
		if strings.HasSuffix(field, "change_percentage_24h_usd") && !coinGeckoNumber(value, false, false) {
			return false
		}
	}
	return coinGeckoNumber(data["updated_at"], true, true)
}
