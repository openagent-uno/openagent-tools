package central

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const maxDocument = 4 << 20
const catalogLifetime = 5 * time.Minute

var ErrInvalidCatalog = errors.New("invalid central connector catalog")
var ErrInvalidResponse = errors.New("invalid central connector response")
var ErrCatalogRollback = errors.New("central catalog revision rollback or drift")

// Registry is immutable. Replace the whole registry when publishing a revision.
type Registry struct {
	revision    uint64
	keyID       string
	key         ed25519.PrivateKey
	descriptors []Descriptor
}

// ComputeContract excludes presentation and operational availability. Changes to
// provider identity, exposed tools, schemas, scope policy or custody change it.
func ComputeContract(d Descriptor) string {
	contract := struct {
		ID         string             `json:"id"`
		Provider   string             `json:"provider"`
		Capability string             `json:"capability"`
		Auth       string             `json:"auth"`
		ReadTools  []string           `json:"read_tools"`
		AgentTools []string           `json:"agent_tools"`
		Operations []domain.Operation `json:"operations"`
		Setup      Setup              `json:"setup"`
	}{d.Item.ID, d.Item.Provider, d.Item.Capability, d.Item.Auth,
		d.Item.ReadTools, d.Item.AgentTools, d.Operations, d.Setup}
	data, err := json.Marshal(contract)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func NewRegistry(revision uint64, keyID string, key ed25519.PrivateKey, descriptors []Descriptor) (*Registry, error) {
	if revision == 0 || !domain.ValidResourceID(keyID) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrInvalidCatalog
	}
	prepared := append([]Descriptor(nil), descriptors...)
	for i := range prepared {
		if prepared[i].ContractSHA256 == "" {
			prepared[i].ContractSHA256 = ComputeContract(prepared[i])
		}
	}
	// Validate before serialization too: InternalOnly is intentionally not a wire
	// field, and must never disappear into a seemingly public operation.
	if validateDescriptors(prepared) != nil {
		return nil, ErrInvalidCatalog
	}
	// Own all slices and schemas: callers cannot mutate signed authorization data.
	data, err := json.Marshal(prepared)
	if err != nil || len(data) > maxDocument {
		return nil, ErrInvalidCatalog
	}
	var owned []Descriptor
	if json.Unmarshal(data, &owned) != nil {
		return nil, ErrInvalidCatalog
	}
	for i := range owned {
		if owned[i].ContractSHA256 == "" {
			owned[i].ContractSHA256 = ComputeContract(owned[i])
		}
	}
	if validateDescriptors(owned) != nil {
		return nil, ErrInvalidCatalog
	}
	return &Registry{revision: revision, keyID: keyID, key: append(ed25519.PrivateKey(nil), key...), descriptors: owned}, nil
}

func (r *Registry) Snapshot(now time.Time) SignedCatalog {
	now = now.UTC()
	payload, _ := json.Marshal(Catalog{Protocol: Protocol, Revision: r.revision,
		IssuedAt: now, ExpiresAt: now.Add(catalogLifetime), Connectors: r.descriptors})
	return SignedCatalog{KeyID: r.keyID, Payload: payload,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(r.key, payload))}
}

func (r *Registry) Lookup(id string) (Descriptor, bool) {
	for _, d := range r.descriptors {
		if d.Item.ID == id {
			data, _ := json.Marshal(d)
			var copy Descriptor
			_ = json.Unmarshal(data, &copy)
			return copy, true
		}
	}
	return Descriptor{}, false
}

func validText(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validateDescriptors(descriptors []Descriptor) error {
	if descriptors == nil || len(descriptors) > 1024 {
		return ErrInvalidCatalog
	}
	seen, total := map[string]bool{}, 0
	for _, d := range descriptors {
		i := d.Item
		if !domain.ValidResourceID(i.ID) || seen[i.ID] || !domain.Capability(i.Capability).Valid() ||
			!domain.ValidResourceID(i.Provider) || i.Provider != strings.ToLower(i.Provider) ||
			i.Name == "" || !validText(i.Name, 256) || !validText(i.Description, 8192) ||
			!validText(i.Category, 128) || !validText(i.Icon, 128) || len(i.LogoSVG) > 64<<10 ||
			!validText(i.SetupURL, 2048) || !validText(i.SetupInstructions, 8192) ||
			!validText(i.UnavailableReason, 2048) || !validHash(d.ContractSHA256) ||
			d.ContractSHA256 != ComputeContract(d) || len(d.Operations) > 2048 {
			return ErrInvalidCatalog
		}
		seen[i.ID] = true
		if i.Auth != "oauth" && i.Auth != "none" && i.Auth != "token" && i.Auth != "credentials" && i.Auth != "custom_mcp" {
			return ErrInvalidCatalog
		}
		if i.Auth != "oauth" && i.Auth != "none" && i.Available {
			return ErrInvalidCatalog
		}
		if d.Setup.Mode != i.Auth || d.Setup.CredentialCustody != "service" || d.Setup.Execution != "service" {
			return ErrInvalidCatalog
		}
		interaction := "hosted"
		if i.Auth == "none" {
			interaction = "none"
		}
		if d.Setup.Interaction != "" && d.Setup.Interaction != interaction {
			return ErrInvalidCatalog
		}
		allowed := map[string]bool{}
		readOnly := map[string]bool{}
		for index, group := range [][]string{i.ReadTools, i.AgentTools} {
			for _, name := range group {
				if name == "" || allowed[name] {
					return ErrInvalidCatalog
				}
				allowed[name] = true
				readOnly[name] = index == 0
			}
		}
		ops := map[string]bool{}
		for _, op := range d.Operations {
			if op.Validate() != nil || op.InternalOnly || op.Mode == domain.OperationRaw || op.Risk == domain.RiskRaw ||
				op.Provider != i.Provider || string(op.Capability) != i.Capability || readOnly[op.Name] != (op.Risk == domain.RiskRead) ||
				!allowed[op.Name] || ops[op.Name] || len(op.InputSchema) > 64<<10 {
				return ErrInvalidCatalog
			}
			var schema map[string]json.RawMessage
			if strictJSON(op.InputSchema, &schema) != nil || schema == nil {
				return ErrInvalidCatalog
			}
			ops[op.Name] = true
		}
		if len(ops) != len(allowed) || i.Available && len(ops) == 0 {
			return ErrInvalidCatalog
		}
		total += len(ops)
		if total > 10000 {
			return ErrInvalidCatalog
		}
	}
	return nil
}

// Reject duplicate keys, trailing documents and unknown typed fields. Signatures
// authenticate bytes; they must not make an ambiguous JSON document acceptable.
func strictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxDocument || !utf8.Valid(data) {
		return ErrInvalidResponse
	}
	parser := json.NewDecoder(bytes.NewReader(data))
	parser.UseNumber()
	if uniqueValue(parser, 0) != nil {
		return ErrInvalidResponse
	}
	if _, err := parser.Token(); err != io.EOF {
		return ErrInvalidResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrInvalidResponse
	}
	return nil
}

func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return ErrInvalidResponse
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidResponse
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInvalidResponse
			}
			seen[name] = true
			if uniqueValue(decoder, depth+1) != nil {
				return ErrInvalidResponse
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidResponse
		}
	case '[':
		for decoder.More() {
			if uniqueValue(decoder, depth+1) != nil {
				return ErrInvalidResponse
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidResponse
		}
	default:
		return ErrInvalidResponse
	}
	return nil
}
