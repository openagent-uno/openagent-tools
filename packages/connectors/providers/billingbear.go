package providers

import "github.com/openagent-uno/openagent-tools/packages/connectors/domain"

// Official API: https://billingbear.io/docs#events-analytics. BillingBear is
// not BillaBear. Only project-scoped secret keys are accepted by this adapter;
// the fixed customer endpoints derive project authority from that key.
func billingbearManifest() Manifest {
	operations := []OperationManifest{
		getOp("commerce.billingbear.project.stats", "Read subscription and revenue metrics for the connected BillingBear project", "/v1/projects/{project_id}/stats", nil, nil),
		getOp("commerce.billingbear.customers.stats", "Read billing statistics for a customer under the connected BillingBear project's secret key", "/v1/customers/{app_user_id}/stats", nil, nil, "app_user_id"),
		getOp("commerce.billingbear.customers.history", "Read a customer's billing event history under the connected BillingBear project's secret key", "/v1/customers/{app_user_id}/history", nil, nil, "app_user_id"),
	}
	for index := range operations {
		properties := map[string]any{}
		if len(operations[index].Required) > 0 {
			properties["app_user_id"] = stringProperty(platformCustomerIDPattern.String())
		}
		operations[index].InputSchema = platformReadSchema("billingbear", properties, operations[index].Required)
	}
	return Manifest{
		Provider: "billingbear", Capability: domain.Commerce, APIVersion: "v1", OriginKind: OriginFixed, Origin: "https://api.billingbear.io",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", ReadOnly: true,
		MaxRequestBytes: 16 << 10, MaxResponseBytes: 4 << 20, Operations: operations,
	}
}
