// Package definitions contains immutable, reviewed connector definitions. These
// are compiled SDK input, never a user-supplied registry or runtime download.
package definitions

import "embed"

//go:embed batch*/providers.json
var documents embed.FS

// Documents returns independent byte slices in deterministic filename order.
func Documents() ([][]byte, error) {
	names, err := documents.ReadDir(".")
	if err != nil {
		return nil, err
	}
	out := [][]byte{}
	for _, name := range names {
		if !name.IsDir() {
			continue
		}
		b, e := documents.ReadFile(name.Name() + "/providers.json")
		if e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, nil
}

// Catalog is deliberately independent of the public catalog package to avoid
// an import cycle. Authentication and operation execution remain in providers.
type Catalog struct {
	SetupURL          string
	SetupInstructions string
	ID                string
	Name              string
	Description       string
	Category          string
	Auth              string
	Icon              string
	Capability        string
	Provider          string
	ReadTools         []string
	AgentTools        []string
	WriteTools        []string
	Available         bool
}
