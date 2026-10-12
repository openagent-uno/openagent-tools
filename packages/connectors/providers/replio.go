package providers

import (
	"encoding/json"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

// These are the organization-scoped REST routes from Replio Platform's
// backend/routes/org_apps.py, org_threads.py and org_data.py. Do not use the
// retired global support API or the unrelated replio.live service.
func replioManifest() Manifest {
	operations := []OperationManifest{
		getOp("outreach.replio.apps.list", "List apps in the connected Replio organization", "/api/v1/orgs/{organization_id}/apps", nil, nil),
		getOp("outreach.replio.threads.list", "Search support threads in the connected Replio organization; follow the returned cursor for more results", "/api/v1/orgs/{organization_id}/threads", map[string]string{
			"app_id": "app_id", "query": "q", "status": "status", "limit": "limit", "cursor": "cursor", "waiting_for_team": "waiting_for_team",
		}, nil),
		getOp("outreach.replio.threads.get", "Read one support thread and its messages from the connected Replio organization", "/api/v1/orgs/{organization_id}/threads/{thread_id}", nil, nil, "thread_id"),
		getOp("outreach.replio.stats.overview", "Read support overview metrics for the connected Replio organization", "/api/v1/orgs/{organization_id}/stats", nil, nil),
	}
	for index := range operations {
		properties := map[string]any{}
		switch operations[index].Name {
		case "outreach.replio.threads.list":
			properties = map[string]any{
				"app_id": stringProperty(platformUUIDPattern.String()), "query": boundedStringProperty(1024),
				"status": map[string]any{"type": "string", "enum": []string{"open", "closed", "archived"}},
				"limit":  integerProperty(1, 200), "cursor": boundedStringProperty(2048), "waiting_for_team": map[string]any{"type": "boolean"},
			}
		case "outreach.replio.threads.get":
			properties["thread_id"] = stringProperty(platformUUIDPattern.String())
		}
		operations[index].InputSchema = platformReadSchema("replio", properties, operations[index].Required)
	}
	return Manifest{
		Provider: "replio", Capability: domain.Outreach, APIVersion: "v1", OriginKind: OriginFixed, Origin: "https://api.replio.to",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", ReadOnly: true,
		MaxRequestBytes: 16 << 10, MaxResponseBytes: 4 << 20, Operations: operations,
	}
}

func platformReadSchema(provider string, properties map[string]any, required []string) json.RawMessage {
	properties["connection_id"] = boundedStringProperty(128)
	properties["provider"] = map[string]any{"type": "string", "const": provider}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}
