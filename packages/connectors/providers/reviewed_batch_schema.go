package providers

import (
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf8"
)

// This is a deliberately closed subset, not a general JSON-schema interpreter.
// Unknown constraints are rejected when the compiled definition is admitted.
type reviewedSchema struct {
	kind             string
	properties       map[string]*reviewedSchema
	required         map[string]bool
	items            *reviewedSchema
	min, max         int
	minimum, maximum float64
	hasMin, hasMax   bool
	pattern          *regexp.Regexp
	values           []any
	constant         any
	hasConstant      bool
}

func reviewedNumber(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, e := n.Float64()
	return f, e == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
}
func reviewedBound(v any, max int) (int, bool) {
	n, ok := reviewedNumber(v)
	return int(n), ok && n >= 0 && n <= float64(max) && math.Trunc(n) == n
}
func compileReviewedSchema(raw any, depth int) (*reviewedSchema, bool) {
	m, ok := raw.(map[string]any)
	if !ok || depth > 8 {
		return nil, false
	}
	s := &reviewedSchema{min: 0, max: 65536, properties: map[string]*reviewedSchema{}, required: map[string]bool{}}
	allowed := map[string]bool{"type": true, "description": true, "title": true, "enum": true, "const": true}
	s.kind, ok = m["type"].(string)
	if !ok {
		return nil, false
	}
	switch s.kind {
	case "object":
		for _, k := range []string{"properties", "required", "additionalProperties", "minProperties", "maxProperties"} {
			allowed[k] = true
		}
		if m["additionalProperties"] != false {
			return nil, false
		}
		p, ok := m["properties"].(map[string]any)
		if !ok || len(p) > 64 {
			return nil, false
		}
		for k, v := range p {
			if !safeArgumentName(k) {
				return nil, false
			}
			nested, ok := compileReviewedSchema(v, depth+1)
			if !ok {
				return nil, false
			}
			s.properties[k] = nested
		}
		s.max = 64
		if v, exists := m["required"]; exists {
			a, ok := v.([]any)
			if !ok {
				return nil, false
			}
			for _, v := range a {
				key, ok := v.(string)
				if !ok || s.properties[key] == nil || s.required[key] {
					return nil, false
				}
				s.required[key] = true
			}
		}
		if v, exists := m["minProperties"]; exists {
			n, ok := reviewedBound(v, 64)
			if !ok {
				return nil, false
			}
			s.min = n
		}
		if v, exists := m["maxProperties"]; exists {
			n, ok := reviewedBound(v, 64)
			if !ok {
				return nil, false
			}
			s.max = n
		}
	case "array":
		for _, k := range []string{"items", "minItems", "maxItems", "uniqueItems"} {
			allowed[k] = true
		}
		nested, ok := compileReviewedSchema(m["items"], depth+1)
		if !ok {
			return nil, false
		}
		s.items = nested
		s.max = 100
		if v, exists := m["minItems"]; exists {
			n, ok := reviewedBound(v, 100)
			if !ok {
				return nil, false
			}
			s.min = n
		}
		v, exists := m["maxItems"]
		if !exists {
			return nil, false
		}
		n, ok := reviewedBound(v, 100)
		if !ok {
			return nil, false
		}
		s.max = n
		if v, exists := m["uniqueItems"]; exists && v != false {
			return nil, false
		}
	case "string":
		for _, k := range []string{"minLength", "maxLength", "pattern", "format"} {
			allowed[k] = true
		}
		s.max = 4096
		if v, exists := m["minLength"]; exists {
			n, ok := reviewedBound(v, 65536)
			if !ok {
				return nil, false
			}
			s.min = n
		}
		if v, exists := m["maxLength"]; exists {
			n, ok := reviewedBound(v, 65536)
			if !ok {
				return nil, false
			}
			s.max = n
		}
		if v, exists := m["pattern"]; exists {
			p, ok := v.(string)
			if !ok || len(p) > 2048 {
				return nil, false
			}
			var e error
			s.pattern, e = regexp.Compile(p)
			if e != nil {
				return nil, false
			}
		}
		if _, exists := m["format"]; exists {
			return nil, false
		}
	case "integer", "number":
		allowed["minimum"], allowed["maximum"] = true, true
		if v, exists := m["minimum"]; exists {
			n, ok := reviewedNumber(v)
			if !ok {
				return nil, false
			}
			s.minimum, s.hasMin = n, true
		}
		if v, exists := m["maximum"]; exists {
			n, ok := reviewedNumber(v)
			if !ok {
				return nil, false
			}
			s.maximum, s.hasMax = n, true
		}
	case "boolean":
	default:
		return nil, false
	}
	if (s.kind == "integer" || s.kind == "number") && (!s.hasMin || !s.hasMax) || s.min > s.max || s.hasMin && s.hasMax && s.minimum > s.maximum {
		return nil, false
	}
	for k := range m {
		if !allowed[k] {
			return nil, false
		}
	}
	if v, exists := m["enum"]; exists {
		a, ok := v.([]any)
		if !ok || len(a) == 0 || len(a) > 100 {
			return nil, false
		}
		s.values = a
	}
	if v, exists := m["const"]; exists {
		s.constant, s.hasConstant = v, true
	}
	return s, true
}
func (s *reviewedSchema) valid(v any) bool {
	if s.hasConstant && !reflect.DeepEqual(v, s.constant) {
		return false
	}
	if len(s.values) > 0 {
		found := false
		for _, item := range s.values {
			if reflect.DeepEqual(v, item) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	switch s.kind {
	case "object":
		m, ok := v.(map[string]any)
		if !ok || len(m) < s.min || len(m) > s.max {
			return false
		}
		for k := range s.required {
			if _, exists := m[k]; !exists {
				return false
			}
		}
		for k, value := range m {
			nested := s.properties[k]
			if nested == nil || !nested.valid(value) {
				return false
			}
		}
		return true
	case "array":
		a, ok := v.([]any)
		if !ok || len(a) < s.min || len(a) > s.max {
			return false
		}
		for _, item := range a {
			if !s.items.valid(item) {
				return false
			}
		}
		return true
	case "string":
		value, ok := v.(string)
		if !ok || !utf8.ValidString(value) || utf8.RuneCountInString(value) < s.min || utf8.RuneCountInString(value) > s.max {
			return false
		}
		for _, r := range value {
			if r == 0 || r == 0x7f || r < 0x20 {
				return false
			}
		}
		return s.pattern == nil || s.pattern.MatchString(value)
	case "integer", "number":
		n, ok := reviewedNumber(v)
		return ok && (s.kind != "integer" || math.Trunc(n) == n) && (!s.hasMin || n >= s.minimum) && (!s.hasMax || n <= s.maximum)
	case "boolean":
		_, ok := v.(bool)
		return ok
	}
	return false
}

type reviewedProjection struct {
	fields map[string]*reviewedProjection
	each   *reviewedProjection
	leaf   bool
}

func reviewedPath(raw string) ([]string, bool) {
	if raw == "" || len(raw) > 512 {
		return nil, false
	}
	parts := []string{}
	for _, segment := range strings.Split(raw, ".") {
		if segment == "[]" {
			parts = append(parts, "[]")
			continue
		}
		array := strings.HasSuffix(segment, "[]")
		name := strings.TrimSuffix(segment, "[]")
		if name == "" || len(name) > 128 {
			return nil, false
		}
		for _, r := range name {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '@') {
				return nil, false
			}
		}
		parts = append(parts, name)
		if array {
			parts = append(parts, "[]")
		}
	}
	return parts, len(parts) <= 12
}
func (p *reviewedProjection) add(parts []string) bool {
	if len(parts) == 0 {
		if len(p.fields) > 0 || p.each != nil {
			return false
		}
		p.leaf = true
		return true
	}
	if p.leaf {
		return false
	}
	if parts[0] == "[]" {
		if len(p.fields) > 0 {
			return false
		}
		if p.each == nil {
			p.each = &reviewedProjection{}
		}
		return p.each.add(parts[1:])
	}
	if p.each != nil {
		return false
	}
	if p.fields == nil {
		p.fields = map[string]*reviewedProjection{}
	}
	if p.fields[parts[0]] == nil {
		p.fields[parts[0]] = &reviewedProjection{}
	}
	return p.fields[parts[0]].add(parts[1:])
}
func (p *reviewedProjection) project(v any) (any, bool) {
	if p.leaf {
		switch v.(type) {
		case nil, string, json.Number, bool:
			return v, true
		default:
			return nil, false
		}
	}
	if p.each != nil {
		a, ok := v.([]any)
		if !ok || len(a) > 10000 {
			return nil, false
		}
		out := make([]any, 0, len(a))
		for _, item := range a {
			row, ok := p.each.project(item)
			if !ok {
				return nil, false
			}
			out = append(out, row)
		}
		return out, true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for k, nested := range p.fields {
		value, exists := m[k]
		if !exists {
			continue
		}
		clean, ok := nested.project(value)
		if !ok {
			return nil, false
		}
		out[k] = clean
	}
	return out, len(out) > 0
}
func reviewedPathValues(v any, parts []string) ([]any, bool) {
	if len(parts) == 0 {
		return []any{v}, true
	}
	if parts[0] == "[]" {
		a, ok := v.([]any)
		if !ok {
			return nil, false
		}
		out := []any{}
		for _, item := range a {
			values, ok := reviewedPathValues(item, parts[1:])
			if !ok {
				return nil, false
			}
			out = append(out, values...)
		}
		return out, true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	value, exists := m[parts[0]]
	if !exists {
		return nil, false
	}
	return reviewedPathValues(value, parts[1:])
}
func reviewedTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case json.Number:
		n, ok := reviewedNumber(x)
		return !ok || n != 0
	default:
		return true
	}
}
