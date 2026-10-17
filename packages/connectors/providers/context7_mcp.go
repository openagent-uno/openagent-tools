package providers

import (
	"errors"
	"regexp"
)

// Official interface: https://context7.com/docs/resources/all-clients and
// https://github.com/upstash/context7/blob/master/packages/mcp/README.md.
// Local bounds narrow the observed Context7 4.4.2 input interface. Metadata
// supplied no outputSchema: only bounded nonempty MCP text is exposed, never
// assumed structured library IDs/results or authenticated/private API data.
const context7LibraryIDPattern = `^/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}(/[A-Za-z0-9][A-Za-z0-9._-]{0,127})?$`

var context7LibraryID = regexp.MustCompile(context7LibraryIDPattern)

func validateContext7MCPResult(result map[string]any) error {
	invalid := errors.New("invalid Context7 tool output")
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 || len(content) > 32 {
		return invalid
	}
	for _, value := range content {
		entry, ok := value.(map[string]any)
		if !ok || entry["type"] != "text" || !keylessMCPText(entry["text"], keylessMCPMaxResponse) {
			return invalid
		}
	}
	return nil
}
