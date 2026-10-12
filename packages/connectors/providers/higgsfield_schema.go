package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// validateHiggsfieldArguments implements the deliberately small JSON Schema
// subset used by the reviewed Higgsfield snapshot. Unsupported schema
// constructs fail during startup, and every remote invocation is checked
// again before crossing the provider boundary.
func validateHiggsfieldArguments(raw json.RawMessage, arguments map[string]any) error {
	schema, err := decodeHiggsfieldSchema(raw)
	if err != nil {
		return domain.ErrInvalidArguments
	}
	if err := validateHiggsfieldSchemaValue(schema, arguments, 0); err != nil {
		return domain.ErrInvalidArguments
	}
	if containsExcludedHiggsfieldInput(arguments, 0) {
		return domain.ErrInvalidArguments
	}
	return nil
}

func validateHiggsfieldSchema(raw json.RawMessage) error {
	schema, err := decodeHiggsfieldSchema(raw)
	if err != nil {
		return err
	}
	if schemaType, _ := schema["type"].(string); schemaType != "object" {
		return errors.New("top-level schema must be an object")
	}
	return inspectHiggsfieldSchema(schema, 0)
}

func decodeHiggsfieldSchema(raw json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var schema map[string]any
	if decoder.Decode(&schema) != nil || decoder.Decode(&struct{}{}) != io.EOF || schema == nil {
		return nil, errors.New("schema is not strict JSON")
	}
	return schema, nil
}

func inspectHiggsfieldSchema(schema map[string]any, depth int) error {
	if depth > 8 || len(schema) > 16 {
		return errors.New("schema is too complex")
	}
	for keyword := range schema {
		switch keyword {
		case "type", "properties", "required", "additionalProperties", "enum",
			"minLength", "maxLength", "minimum", "maximum", "maxProperties",
			"items", "minItems", "maxItems", "description":
		default:
			return errors.New("schema contains an unsupported keyword")
		}
	}
	schemaType, ok := schema["type"].(string)
	if !ok {
		return errors.New("schema type is required")
	}
	switch schemaType {
	case "object":
		properties := map[string]any{}
		if rawProperties, present := schema["properties"]; present {
			var ok bool
			properties, ok = rawProperties.(map[string]any)
			if !ok {
				return errors.New("object properties are invalid")
			}
		}
		if len(properties) > 128 {
			return errors.New("object properties are invalid")
		}
		for name, rawProperty := range properties {
			if !safeHiggsfieldPropertyName(name) {
				return errors.New("property name is invalid")
			}
			property, ok := rawProperty.(map[string]any)
			if !ok || inspectHiggsfieldSchema(property, depth+1) != nil {
				return errors.New("property schema is invalid")
			}
		}
		if rawRequired, present := schema["required"]; present {
			required, ok := rawRequired.([]any)
			if !ok || len(required) > len(properties) {
				return errors.New("required properties are invalid")
			}
			seen := make(map[string]bool, len(required))
			for _, value := range required {
				name, ok := value.(string)
				if !ok || seen[name] {
					return errors.New("required property is invalid")
				}
				if _, exists := properties[name]; !exists {
					return errors.New("required property is unknown")
				}
				seen[name] = true
			}
		}
		if additional, present := schema["additionalProperties"]; present {
			if _, ok := additional.(bool); !ok {
				return errors.New("additionalProperties must be boolean")
			}
		}
		if _, ok := boundedSchemaInteger(schema["maxProperties"], 0, 1024); schema["maxProperties"] != nil && !ok {
			return errors.New("maxProperties is invalid")
		}
	case "array":
		items, ok := schema["items"].(map[string]any)
		if !ok || inspectHiggsfieldSchema(items, depth+1) != nil {
			return errors.New("array item schema is invalid")
		}
		if _, ok := boundedSchemaInteger(schema["minItems"], 0, 1024); schema["minItems"] != nil && !ok {
			return errors.New("minItems is invalid")
		}
		if _, ok := boundedSchemaInteger(schema["maxItems"], 0, 1024); schema["maxItems"] != nil && !ok {
			return errors.New("maxItems is invalid")
		}
	case "string":
		if _, ok := boundedSchemaInteger(schema["minLength"], 0, 1<<20); schema["minLength"] != nil && !ok {
			return errors.New("minLength is invalid")
		}
		if _, ok := boundedSchemaInteger(schema["maxLength"], 0, 1<<20); schema["maxLength"] != nil && !ok {
			return errors.New("maxLength is invalid")
		}
	case "integer", "number", "boolean":
	default:
		return errors.New("schema type is unsupported")
	}
	if rawEnum, present := schema["enum"]; present {
		values, ok := rawEnum.([]any)
		if !ok || len(values) == 0 || len(values) > 256 {
			return errors.New("schema enum is invalid")
		}
		for _, value := range values {
			if !schemaValueMatchesType(schemaType, value) {
				return errors.New("schema enum has an invalid value")
			}
			if text, ok := value.(string); ok && excludedHiggsfieldIdentifier(text) {
				return errors.New("schema enum contains an excluded identity or voice feature")
			}
		}
	}
	return nil
}

func validateHiggsfieldSchemaValue(schema map[string]any, value any, depth int) error {
	if depth > 8 {
		return errors.New("arguments are too deeply nested")
	}
	schemaType, _ := schema["type"].(string)
	if !schemaValueMatchesType(schemaType, value) {
		return errors.New("argument type does not match schema")
	}
	if rawEnum, present := schema["enum"]; present {
		matched := false
		for _, allowed := range rawEnum.([]any) {
			if equalSchemaScalar(value, allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("argument is outside reviewed enum")
		}
	}
	switch schemaType {
	case "object":
		object := value.(map[string]any)
		if maximum, ok := boundedSchemaInteger(schema["maxProperties"], 0, 1024); ok && len(object) > maximum {
			return errors.New("object has too many properties")
		}
		properties, _ := schema["properties"].(map[string]any)
		if properties == nil {
			properties = map[string]any{}
		}
		additional, _ := schema["additionalProperties"].(bool)
		for key, nested := range object {
			rawProperty, exists := properties[key]
			if !exists {
				if !additional {
					return errors.New("unknown argument property")
				}
				if !safeHiggsfieldJSONValue(nested, depth+1) {
					return errors.New("additional argument is invalid")
				}
				continue
			}
			if err := validateHiggsfieldSchemaValue(rawProperty.(map[string]any), nested, depth+1); err != nil {
				return err
			}
		}
		if required, ok := schema["required"].([]any); ok {
			for _, rawName := range required {
				if _, exists := object[rawName.(string)]; !exists {
					return errors.New("required argument is missing")
				}
			}
		}
	case "array":
		array := value.([]any)
		if minimum, ok := boundedSchemaInteger(schema["minItems"], 0, 1024); ok && len(array) < minimum {
			return errors.New("array is too short")
		}
		if maximum, ok := boundedSchemaInteger(schema["maxItems"], 0, 1024); ok && len(array) > maximum {
			return errors.New("array is too long")
		}
		items := schema["items"].(map[string]any)
		for _, nested := range array {
			if err := validateHiggsfieldSchemaValue(items, nested, depth+1); err != nil {
				return err
			}
		}
	case "string":
		text := value.(string)
		if strings.ContainsRune(text, '\x00') {
			return errors.New("string contains a forbidden control byte")
		}
		length := len([]rune(text))
		if minimum, ok := boundedSchemaInteger(schema["minLength"], 0, 1<<20); ok && length < minimum {
			return errors.New("string is too short")
		}
		if maximum, ok := boundedSchemaInteger(schema["maxLength"], 0, 1<<20); ok && length > maximum {
			return errors.New("string is too long")
		}
	case "integer", "number":
		number := value.(json.Number)
		if minimum, ok := schemaNumber(schema["minimum"]); ok {
			actual, _ := number.Float64()
			if actual < minimum {
				return errors.New("number is below minimum")
			}
		}
		if maximum, ok := schemaNumber(schema["maximum"]); ok {
			actual, _ := number.Float64()
			if actual > maximum {
				return errors.New("number is above maximum")
			}
		}
	}
	return nil
}

func schemaValueMatchesType(schemaType string, value any) bool {
	switch schemaType {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := number.Int64()
		return err == nil
	case "number":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		parsed, err := number.Float64()
		return err == nil && !math.IsInf(parsed, 0) && !math.IsNaN(parsed)
	default:
		return false
	}
}

func equalSchemaScalar(left, right any) bool {
	switch typed := left.(type) {
	case string:
		other, ok := right.(string)
		return ok && typed == other
	case bool:
		other, ok := right.(bool)
		return ok && typed == other
	case json.Number:
		other, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftNumber, leftErr := typed.Float64()
		rightNumber, rightErr := other.Float64()
		return leftErr == nil && rightErr == nil && leftNumber == rightNumber
	default:
		return false
	}
}

func boundedSchemaInteger(value any, minimum, maximum int) (int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	return int(parsed), err == nil && parsed >= int64(minimum) && parsed <= int64(maximum)
}

func schemaNumber(value any) (float64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Float64()
	return parsed, err == nil && !math.IsInf(parsed, 0) && !math.IsNaN(parsed)
}

func safeHiggsfieldPropertyName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func safeHiggsfieldJSONValue(value any, depth int) bool {
	if depth > 8 {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > 128 {
			return false
		}
		for key, nested := range typed {
			if !safeHiggsfieldPropertyName(key) || !safeHiggsfieldJSONValue(nested, depth+1) {
				return false
			}
		}
	case []any:
		if len(typed) > 128 {
			return false
		}
		for _, nested := range typed {
			if !safeHiggsfieldJSONValue(nested, depth+1) {
				return false
			}
		}
	case string:
		return len(typed) <= 64<<10 && !strings.ContainsRune(typed, '\x00')
	case json.Number:
		_, ok := schemaNumber(typed)
		return ok
	case bool, nil:
	default:
		return false
	}
	return true
}

func containsExcludedHiggsfieldInput(value any, depth int) bool {
	if depth > 8 {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if excludedHiggsfieldIdentifier(key) {
				return true
			}
			if containsExcludedHiggsfieldInput(nested, depth+1) {
				return true
			}
		}
	case []any:
		for _, nested := range typed {
			if containsExcludedHiggsfieldInput(nested, depth+1) {
				return true
			}
		}
	}
	return false
}

func excludedHiggsfieldIdentifier(value string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(value, "-", "_"), ".", "_"))
	for _, blocked := range []string{"soul_id", "face", "identity", "train", "clone", "voice"} {
		if strings.Contains(normalized, blocked) {
			return true
		}
	}
	return false
}
