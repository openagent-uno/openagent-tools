package central

import _ "embed"

//go:embed protocol-v1.schema.json
var protocolSchema []byte

// ProtocolSchema returns the bounded, versioned public transport schema. It
// describes data shapes and never replaces signature or authorization checks.
func ProtocolSchema() []byte { return append([]byte(nil), protocolSchema...) }
