package providers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	defaultMaxRequestBytes   = int64(8 << 20)
	defaultMaxResponseBytes  = int64(16 << 20)
	defaultGmailRequestBytes = int64(12 << 20)
	// One in-memory payload, at most 16 MiB before base64 encoding.
	// Keep the expanded request bounded below the manifest hard ceiling.
	defaultDriveMaxRequestBytes = int64(24 << 20)
)

var (
	readRetry = RetrySpec{
		MaxAttempts: 3, BaseDelay: 200 * time.Millisecond, MaxDelay: 2 * time.Second,
		Statuses: []int{http.StatusRequestTimeout, http.StatusTooManyRequests, 500, 502, 503, 504},
	}
	idempotentWriteRetry = RetrySpec{
		MaxAttempts: 3, BaseDelay: 200 * time.Millisecond, MaxDelay: 2 * time.Second,
		Statuses: []int{http.StatusRequestTimeout, http.StatusTooManyRequests, 500, 502, 503, 504}, RetryableWrite: true,
	}
	noRetry = RetrySpec{MaxAttempts: 1}
)

func Manifests() []Manifest {
	return []Manifest{shopifyManifest(), driveManifest(), gmailManifest(), postizManifest(), pipeboardManifest(), googleAnalyticsManifest(), replioManifest(), billingbearManifest(), clickupManifest(), githubManifest(), notionManifest(), slackManifest(), atlassianManifest()}
}

func shopifyManifest() Manifest {
	graphqlPath := "/admin/api/" + ShopifyAPIVersion + "/graphql.json"
	unrestrictedScopes := []string{
		"write_products", "write_orders", "write_customers", "write_inventory",
		"write_themes", "write_merchant_managed_fulfillment_orders",
	}
	gql := func(name, description string, risk domain.Risk, document string, sync *SyncSpec, required ...string) OperationManifest {
		retry := noRetry
		if risk == domain.RiskRead {
			retry = readRetry
		} else if risk == domain.RiskDraft || risk == domain.RiskWrite {
			retry = idempotentWriteRetry
		}
		return OperationManifest{
			Name: name, Description: description, Risk: risk, Method: http.MethodPost, Path: graphqlPath,
			Required: required, Body: BodyGraphQL, GraphQLDocument: document, InputSchema: typedSchema(required...), IdempotencyHeader: "Idempotency-Key", Retry: retry, Sync: sync,
		}
	}
	productSync := &SyncSpec{Strategy: "webhook_reconcile", CursorField: "endCursor", WebhookCapable: true, Resource: "products"}
	orderSync := &SyncSpec{Strategy: "webhook_reconcile", CursorField: "endCursor", WebhookCapable: true, Resource: "orders"}
	customerSync := &SyncSpec{Strategy: "webhook_reconcile", CursorField: "endCursor", WebhookCapable: true, Resource: "customers"}
	operations := []OperationManifest{
		gql("commerce.shopify.products.list", "List products with inventory quantity, tracking state, precision-aware total and variant counts, and cursor completeness metadata", domain.RiskRead, `query Products($first:Int=50,$after:String,$query:String){productsCount(query:$query,limit:null){count precision}products(first:$first,after:$after,query:$query){nodes{id title handle status tags updatedAt totalInventory tracksInventory variantsCount{count precision} variants(first:100){nodes{id title sku price inventoryQuantity}pageInfo{hasNextPage endCursor}}}pageInfo{hasNextPage endCursor}}}`, productSync).withRequiredScopes("read_products", "read_inventory"),
		gql("commerce.shopify.products.get", "Read one product with inventory quantity, tracking state, and variant completeness metadata", domain.RiskRead, `query Product($id:ID!){product(id:$id){id title descriptionHtml handle status tags vendor productType updatedAt totalInventory tracksInventory variantsCount{count precision} variants(first:250){nodes{id title sku barcode price compareAtPrice inventoryQuantity}pageInfo{hasNextPage endCursor}}}}`, productSync).withRequiredScopes("read_products", "read_inventory"),
		{
			Name: "commerce.shopify.products.variants.list", Description: "List one product's variants with cursor pagination; follow pageInfo until hasNextPage is false before treating the result as complete", Risk: domain.RiskRead,
			Method: http.MethodPost, Path: graphqlPath, Required: []string{"product_id"}, RequiredScopes: []string{"read_products", "read_inventory"}, Body: BodyGraphQL,
			GraphQLDocument:       `query ProductVariants($first:Int=100,$after:String,$productFilter:String!){productVariants(first:$first,after:$after,query:$productFilter){nodes{id title sku barcode price compareAtPrice inventoryQuantity updatedAt product{id title handle}}pageInfo{hasNextPage endCursor}}}`,
			GraphQLIDSearchFilter: &GraphQLIDSearchFilter{InputVariable: "product_id", QueryVariable: "productFilter", FilterName: "product_id", GIDType: "Product"},
			InputSchema:           shopifyProductVariantsSchema(), Retry: readRetry,
		},
		gql("commerce.shopify.products.create", "Create a product", domain.RiskWrite, `mutation ProductCreate($product:ProductCreateInput!){productCreate(product:$product){product{id title status}userErrors{field message code}}}`, productSync).withRequiredScopes("write_products"),
		gql("commerce.shopify.products.update", "Update a product", domain.RiskWrite, `mutation ProductUpdate($product:ProductUpdateInput!){productUpdate(product:$product){product{id title status updatedAt}userErrors{field message}}}`, productSync).withRequiredScopes("write_products"),
		gql("commerce.shopify.products.delete", "Delete a product", domain.RiskDestructive, `mutation ProductDelete($input:ProductDeleteInput!){productDelete(input:$input){deletedProductId userErrors{field message}}}`, productSync).withRequiredScopes("write_products"),
		gql("commerce.shopify.collections.list", "List collections", domain.RiskRead, `query Collections($first:Int=50,$after:String,$query:String){collections(first:$first,after:$after,query:$query){nodes{id title handle updatedAt}pageInfo{hasNextPage endCursor}}}`, &SyncSpec{Strategy: "webhook_reconcile", CursorField: "endCursor", WebhookCapable: true, Resource: "collections"}).withRequiredScopes("read_products"),
		gql("commerce.shopify.collections.get", "Read one collection", domain.RiskRead, `query Collection($id:ID!){collection(id:$id){id title descriptionHtml handle updatedAt products(first:100){nodes{id title}}}}`, nil).withRequiredScopes("read_products"),
		gql("commerce.shopify.collections.create", "Create a collection", domain.RiskWrite, `mutation CollectionCreate($input:CollectionInput!){collectionCreate(input:$input){collection{id title}userErrors{field message}}}`, nil).withRequiredScopes("write_products"),
		gql("commerce.shopify.collections.update", "Update a collection", domain.RiskWrite, `mutation CollectionUpdate($input:CollectionInput!){collectionUpdate(input:$input){collection{id title updatedAt}userErrors{field message}}}`, nil).withRequiredScopes("write_products"),
		gql("commerce.shopify.collections.delete", "Delete a collection", domain.RiskDestructive, `mutation CollectionDelete($input:CollectionDeleteInput!){collectionDelete(input:$input){deletedCollectionId userErrors{field message}}}`, nil).withRequiredScopes("write_products"),
		gql("commerce.shopify.orders.list", "List minimized non-identifying order financials with line-item cost coverage and cursor pagination", domain.RiskRead, `query Orders($first:Int=50,$after:String,$query:String){shop{currencyCode ianaTimezone}orders(first:$first,after:$after,query:$query){nodes{id name createdAt processedAt updatedAt test cancelledAt displayFinancialStatus displayFulfillmentStatus currentSubtotalPriceSet{shopMoney{amount currencyCode}}currentTotalPriceSet{shopMoney{amount currencyCode}}currentTotalTaxSet{shopMoney{amount currencyCode}}currentShippingPriceSet{shopMoney{amount currencyCode}}currentTotalDutiesSet{shopMoney{amount currencyCode}}currentTotalDiscountsSet{shopMoney{amount currencyCode}}lineItems(first:250){nodes{id title sku currentQuantity priceAfterAllDiscountsBeforeTaxesSet{shopMoney{amount currencyCode}}variant{inventoryItem{unitCost{amount currencyCode}}}}pageInfo{hasNextPage endCursor}}}pageInfo{hasNextPage endCursor}}}`, orderSync).withRequiredScopes("read_orders", "read_inventory"),
		gql("commerce.shopify.orders.get", "Read one minimized non-identifying order with financials, line items, and transactions", domain.RiskRead, `query Order($id:ID!){order(id:$id){id name createdAt processedAt updatedAt test cancelledAt displayFinancialStatus displayFulfillmentStatus currentSubtotalPriceSet{shopMoney{amount currencyCode}}currentTotalPriceSet{shopMoney{amount currencyCode}}currentTotalTaxSet{shopMoney{amount currencyCode}}currentShippingPriceSet{shopMoney{amount currencyCode}}currentTotalDutiesSet{shopMoney{amount currencyCode}}currentTotalDiscountsSet{shopMoney{amount currencyCode}}lineItems(first:250){nodes{id title sku currentQuantity priceAfterAllDiscountsBeforeTaxesSet{shopMoney{amount currencyCode}}variant{inventoryItem{unitCost{amount currencyCode}}}}pageInfo{hasNextPage endCursor}}transactions{id status kind amountSet{shopMoney{amount currencyCode}}}}}`, orderSync).withRequiredScopes("read_orders", "read_inventory"),
		gql("commerce.shopify.orders.cancel", "Cancel an order", domain.RiskDestructive, `mutation OrderCancel($orderId:ID!,$reason:OrderCancelReason!,$refund:Boolean!,$restock:Boolean!,$notifyCustomer:Boolean){orderCancel(orderId:$orderId,reason:$reason,refund:$refund,restock:$restock,notifyCustomer:$notifyCustomer){orderCancelUserErrors{field message}job{id done}}}`, orderSync).withRequiredScopes("write_orders"),
		gql("commerce.shopify.orders.close", "Close an order", domain.RiskWrite, `mutation OrderClose($input:OrderCloseInput!){orderClose(input:$input){order{id closed}userErrors{field message}}}`, orderSync).withRequiredScopes("write_orders"),
		gql("commerce.shopify.customers.list", "List customers with cursor pagination", domain.RiskRead, `query Customers($first:Int=50,$after:String,$query:String){customers(first:$first,after:$after,query:$query){nodes{id displayName email updatedAt}pageInfo{hasNextPage endCursor}}}`, customerSync).withRequiredScopes("read_customers"),
		gql("commerce.shopify.customers.get", "Read one customer and recent orders", domain.RiskRead, `query Customer($id:ID!){customer(id:$id){id displayName email updatedAt orders(first:25){nodes{id name createdAt}}}}`, customerSync).withRequiredScopes("read_customers", "read_orders"),
		gql("commerce.shopify.customers.update", "Update a customer", domain.RiskWrite, `mutation CustomerUpdate($input:CustomerInput!){customerUpdate(input:$input){customer{id displayName updatedAt}userErrors{field message}}}`, customerSync).withRequiredScopes("write_customers"),
		gql("commerce.shopify.inventory.levels.list", "List inventory items and available quantities by inventory level with cursor pagination", domain.RiskRead, `query InventoryLevels($first:Int=20,$after:String,$query:String){inventoryItems(first:$first,after:$after,query:$query){nodes{id sku tracked inventoryLevels(first:10){nodes{id quantities(names:["available"]){name quantity}}pageInfo{hasNextPage endCursor}}}pageInfo{hasNextPage endCursor}}}`, &SyncSpec{Strategy: "webhook_reconcile", CursorField: "endCursor", WebhookCapable: true, Resource: "inventory"}).withRequiredScopes("read_inventory"),
		gql("commerce.shopify.inventory.adjust", "Adjust inventory quantities", domain.RiskWrite, `mutation InventoryAdjust($input:InventoryAdjustQuantitiesInput!,$idempotencyKey:String!){inventoryAdjustQuantities(input:$input) @idempotent(key:$idempotencyKey){inventoryAdjustmentGroup{createdAt reason changes{name delta}}userErrors{field message}}}`, nil).withGraphQLIdempotency("idempotencyKey").withRequiredScopes("write_inventory"),
		gql("commerce.shopify.fulfillments.create", "Create a fulfilment", domain.RiskPublish, `mutation FulfillmentCreate($fulfillment:FulfillmentV2Input!,$message:String){fulfillmentCreateV2(fulfillment:$fulfillment,message:$message){fulfillment{id status}userErrors{field message}}}`, nil).withRequiredScopes("write_merchant_managed_fulfillment_orders"),
		gql("commerce.shopify.refunds.create", "Create an order refund", domain.RiskDestructive, `mutation RefundCreate($input:RefundInput!,$idempotencyKey:String!){refundCreate(input:$input) @idempotent(key:$idempotencyKey){refund{id createdAt}userErrors{field message}}}`, nil).withGraphQLIdempotency("idempotencyKey").withRequiredScopes("write_orders"),
		gql("commerce.shopify.analytics.shopifyql", "Run a ShopifyQL analytics query", domain.RiskRead, `query ShopifyQL($query:String!){shop{currencyCode ianaTimezone}shopifyqlQuery(query:$query){tableData{columns{name dataType displayName}rows}parseErrors}}`, &SyncSpec{Strategy: "snapshot", Resource: "analytics"}).withRequiredScopes("read_reports"),
		gql("commerce.shopify.bulk.run", "Start a bulk GraphQL query", domain.RiskWrite, `mutation BulkRun($query:String!){bulkOperationRunQuery(query:$query){bulkOperation{id status}userErrors{field message}}}`, &SyncSpec{Strategy: "bulk_poll", CursorField: "id", WebhookCapable: true, Resource: "bulk_operations"}).withRequiredScopes("read_products", "read_orders", "read_customers", "read_inventory", "read_reports"),
		gql("commerce.shopify.bulk.current", "Read the current bulk operation", domain.RiskRead, `query CurrentBulk{currentBulkOperation{id status errorCode objectCount fileSize url partialDataUrl createdAt completedAt}}`, nil).withRequiredScopes("read_products", "read_orders", "read_customers", "read_inventory", "read_reports"),
		gql("commerce.shopify.app.access_scopes", "Read the access scopes currently granted to this app installation", domain.RiskRead, `query CurrentAppAccessScopes{currentAppInstallation{accessScopes{handle}}}`, nil),
		{Name: "commerce.shopify.graphql", Description: "Execute a GraphQL Admin API document at the fixed API version", Risk: domain.RiskRaw, Method: http.MethodPost, Path: graphqlPath, RequiredScopes: append([]string(nil), unrestrictedScopes...), Body: BodyJSON, InputSchema: typedSchema(), IdempotencyHeader: "Idempotency-Key", Retry: idempotentWriteRetry},
		gql("commerce.shopify.themes.list", "List Online Store themes", domain.RiskRead, `query Themes($first:Int=50,$after:String,$names:[String!],$roles:[ThemeRole!]){themes(first:$first,after:$after,names:$names,roles:$roles){nodes{id name role createdAt updatedAt processing processingFailed themeStoreId}pageInfo{hasNextPage endCursor}}}`, nil).withRequiredScopes("read_themes"),
		gql("commerce.shopify.themes.publish", "Publish a theme (write_themes exemption and feature gates required)", domain.RiskPublish, `mutation ThemePublish($theme_id:ID!){themePublish(id:$theme_id){theme{id name role updatedAt}userErrors{field message}}}`, nil, "theme_id").withRequiredScopes("write_themes"),
		gql("commerce.shopify.theme_files.list", "List files in a theme", domain.RiskRead, `query ThemeFiles($theme_id:ID!,$first:Int=50,$after:String,$filenames:[String!]){theme(id:$theme_id){id files(first:$first,after:$after,filenames:$filenames){nodes{filename checksumMd5 contentType createdAt size updatedAt}pageInfo{hasNextPage endCursor}userErrors{code filename}}}}`, nil, "theme_id").withRequiredScopes("read_themes"),
		gql("commerce.shopify.theme_files.get", "Read one theme file", domain.RiskRead, `query ThemeFile($theme_id:ID!,$asset_key:String!){theme(id:$theme_id){id files(first:1,filenames:[$asset_key]){nodes{filename checksumMd5 contentType createdAt size updatedAt body{... on OnlineStoreThemeFileBodyBase64{contentBase64}... on OnlineStoreThemeFileBodyText{content}... on OnlineStoreThemeFileBodyUrl{url}}}userErrors{code filename}}}}`, nil, "theme_id", "asset_key").withRequiredScopes("read_themes"),
		gql("commerce.shopify.theme_files.write", "Create or update theme files (write_themes exemption and feature gates required)", domain.RiskPublish, `mutation ThemeFilesUpsert($theme_id:ID!,$files:[OnlineStoreThemeFilesUpsertFileInput!]!){themeFilesUpsert(themeId:$theme_id,files:$files){upsertedThemeFiles{filename}job{id done}userErrors{field message}}}`, nil, "theme_id", "files").withRequiredScopes("write_themes"),
		gql("commerce.shopify.theme_files.delete", "Delete theme files (write_themes exemption and feature gates required)", domain.RiskDestructive, `mutation ThemeFilesDelete($theme_id:ID!,$files:[String!]!){themeFilesDelete(themeId:$theme_id,files:$files){deletedThemeFiles{filename}userErrors{field message}}}`, nil, "theme_id", "files").withRequiredScopes("write_themes"),
		gql("commerce.shopify.webhook_subscriptions.list", "List app webhook subscriptions with cursor pagination", domain.RiskRead, `query WebhookSubscriptions($first:Int!,$after:String){webhookSubscriptions(first:$first,after:$after){nodes{id topic uri}pageInfo{hasNextPage endCursor}}}`, nil).internalOnly(),
		gql("commerce.shopify.webhook_subscriptions.create", "Create an app webhook subscription", domain.RiskWrite, `mutation WebhookSubscriptionCreate($topic:WebhookSubscriptionTopic!,$webhookSubscription:WebhookSubscriptionInput!){webhookSubscriptionCreate(topic:$topic,webhookSubscription:$webhookSubscription){webhookSubscription{id topic uri}userErrors{field message}}}`, nil).withoutRetry().internalOnly(),
		gql("commerce.shopify.webhook_subscriptions.delete", "Delete an app webhook subscription", domain.RiskDestructive, `mutation WebhookSubscriptionDelete($id:ID!){webhookSubscriptionDelete(id:$id){deletedWebhookSubscriptionId userErrors{field message}}}`, nil).internalOnly(),
		{Name: "commerce.shopify.raw", Description: "Call the Shopify GraphQL Admin API on this shop and fixed API version", Risk: domain.RiskRaw, RequiredScopes: append([]string(nil), unrestrictedScopes...), Body: BodyRaw, InputSchema: rawSchema(), Retry: idempotentWriteRetry, IdempotencyHeader: "Idempotency-Key", Raw: &RawPolicy{Methods: []string{http.MethodPost}, PathPrefixes: []string{graphqlPath}}},
	}
	return Manifest{Provider: "shopify", Capability: domain.Commerce, APIVersion: ShopifyAPIVersion, OriginKind: OriginShopify, CredentialHeader: "X-Shopify-Access-Token", MaxRequestBytes: defaultMaxRequestBytes, MaxResponseBytes: defaultMaxResponseBytes, Operations: operations}
}

func driveManifest() Manifest {
	fileSync := &SyncSpec{Strategy: "changes_feed", CursorField: "newStartPageToken", WebhookCapable: true, Resource: "files"}
	operations := []OperationManifest{
		getOp("files.drive.search", "Search files and folders", "/drive/v3/files", map[string]string{"query": "q", "page_size": "pageSize", "page_token": "pageToken", "spaces": "spaces", "order_by": "orderBy", "fields": "fields", "corpora": "corpora", "drive_id": "driveId", "include_items_from_all_drives": "includeItemsFromAllDrives", "supports_all_drives": "supportsAllDrives"}, fileSync),
		getOp("files.drive.files.get", "Read file metadata", "/drive/v3/files/{file_id}", map[string]string{"fields": "fields", "supports_all_drives": "supportsAllDrives", "acknowledge_abuse": "acknowledgeAbuse"}, fileSync, "file_id"),
		getOp("files.drive.files.download", "Download file content", "/drive/v3/files/{file_id}", map[string]string{"acknowledge_abuse": "acknowledgeAbuse"}, nil, "file_id").withFixedQuery("alt", "media"),
		getOp("files.drive.files.export", "Export a Google Workspace document", "/drive/v3/files/{file_id}/export", map[string]string{"mime_type": "mimeType"}, nil, "file_id", "mime_type"),
		getOp("files.drive.files.generate_ids", "Generate provider IDs for safely retryable file creates", "/drive/v3/files/generateIds", map[string]string{"count": "count", "space": "space", "type": "type"}, nil),
		writeOp("files.drive.files.create", "Create file or folder metadata", domain.RiskWrite, http.MethodPost, "/drive/v3/files", map[string]string{"supports_all_drives": "supportsAllDrives", "fields": "fields"}, fileSync),
		{
			Name: "files.drive.files.content.create", Description: "Create a file with content using bounded media, multipart, or resumable upload", Risk: domain.RiskWrite,
			Method: http.MethodPost, Path: "/upload/drive/v3/files",
			Query: map[string]string{
				"fields": "fields", "ignore_default_visibility": "ignoreDefaultVisibility",
				"include_permissions_for_view": "includePermissionsForView", "keep_revision_forever": "keepRevisionForever",
				"ocr_language": "ocrLanguage", "supports_all_drives": "supportsAllDrives",
				"use_content_as_indexable_text": "useContentAsIndexableText",
			},
			Required: []string{"content_base64", "mime_type"}, Body: BodyDriveUpload,
			InputSchema: driveUploadSchema(false), Retry: idempotentWriteRetry, Sync: fileSync,
		},
		writeOp("files.drive.files.update", "Update file metadata", domain.RiskWrite, http.MethodPatch, "/drive/v3/files/{file_id}", map[string]string{"add_parents": "addParents", "remove_parents": "removeParents", "supports_all_drives": "supportsAllDrives", "fields": "fields"}, fileSync, "file_id"),
		{
			Name: "files.drive.files.content.update", Description: "Replace file content using bounded media, multipart, or resumable upload", Risk: domain.RiskWrite,
			Method: http.MethodPatch, Path: "/upload/drive/v3/files/{file_id}",
			Query: map[string]string{
				"add_parents": "addParents", "fields": "fields", "include_permissions_for_view": "includePermissionsForView",
				"keep_revision_forever": "keepRevisionForever", "ocr_language": "ocrLanguage",
				"remove_parents": "removeParents", "supports_all_drives": "supportsAllDrives",
				"use_content_as_indexable_text": "useContentAsIndexableText",
			},
			Required: []string{"file_id", "content_base64", "mime_type"}, Body: BodyDriveUpload,
			InputSchema: driveUploadSchema(true), Retry: idempotentWriteRetry, Sync: fileSync,
		},
		writeOp("files.drive.files.copy", "Copy a file", domain.RiskWrite, http.MethodPost, "/drive/v3/files/{file_id}/copy", map[string]string{"supports_all_drives": "supportsAllDrives", "fields": "fields"}, fileSync, "file_id"),
		writeOp("files.drive.files.delete", "Permanently delete a file", domain.RiskDestructive, http.MethodDelete, "/drive/v3/files/{file_id}", map[string]string{"supports_all_drives": "supportsAllDrives"}, fileSync, "file_id").withoutRetry(),
		getOp("files.drive.permissions.list", "List file permissions", "/drive/v3/files/{file_id}/permissions", map[string]string{"page_size": "pageSize", "page_token": "pageToken", "supports_all_drives": "supportsAllDrives", "fields": "fields"}, nil, "file_id"),
		getOp("files.drive.permissions.get", "Read one file permission", "/drive/v3/files/{file_id}/permissions/{permission_id}", map[string]string{"supports_all_drives": "supportsAllDrives", "fields": "fields"}, nil, "file_id", "permission_id"),
		writeOp("files.drive.permissions.create", "Create a file permission", domain.RiskPublish, http.MethodPost, "/drive/v3/files/{file_id}/permissions", map[string]string{"email_message": "emailMessage", "send_notification_email": "sendNotificationEmail", "supports_all_drives": "supportsAllDrives", "transfer_ownership": "transferOwnership", "fields": "fields"}, nil, "file_id"),
		writeOp("files.drive.permissions.update", "Update a file permission", domain.RiskPublish, http.MethodPatch, "/drive/v3/files/{file_id}/permissions/{permission_id}", map[string]string{"supports_all_drives": "supportsAllDrives", "transfer_ownership": "transferOwnership", "fields": "fields"}, nil, "file_id", "permission_id"),
		writeOp("files.drive.permissions.delete", "Delete a file permission", domain.RiskDestructive, http.MethodDelete, "/drive/v3/files/{file_id}/permissions/{permission_id}", map[string]string{"supports_all_drives": "supportsAllDrives"}, nil, "file_id", "permission_id").withoutRetry(),
		getOp("files.drive.comments.list", "List file comments", "/drive/v3/files/{file_id}/comments", map[string]string{"page_size": "pageSize", "page_token": "pageToken", "include_deleted": "includeDeleted", "start_modified_time": "startModifiedTime", "fields": "fields"}, nil, "file_id"),
		getOp("files.drive.comments.get", "Read one file comment", "/drive/v3/files/{file_id}/comments/{comment_id}", map[string]string{"include_deleted": "includeDeleted", "fields": "fields"}, nil, "file_id", "comment_id"),
		writeOp("files.drive.comments.create", "Create a file comment", domain.RiskWrite, http.MethodPost, "/drive/v3/files/{file_id}/comments", map[string]string{"fields": "fields"}, nil, "file_id"),
		writeOp("files.drive.comments.update", "Update a file comment", domain.RiskWrite, http.MethodPatch, "/drive/v3/files/{file_id}/comments/{comment_id}", map[string]string{"fields": "fields"}, nil, "file_id", "comment_id"),
		writeOp("files.drive.comments.delete", "Delete a file comment", domain.RiskDestructive, http.MethodDelete, "/drive/v3/files/{file_id}/comments/{comment_id}", nil, nil, "file_id", "comment_id").withoutRetry(),
		getOp("files.drive.replies.list", "List replies to a file comment", "/drive/v3/files/{file_id}/comments/{comment_id}/replies", map[string]string{"page_size": "pageSize", "page_token": "pageToken", "include_deleted": "includeDeleted", "fields": "fields"}, nil, "file_id", "comment_id"),
		getOp("files.drive.replies.get", "Read one reply to a file comment", "/drive/v3/files/{file_id}/comments/{comment_id}/replies/{reply_id}", map[string]string{"include_deleted": "includeDeleted", "fields": "fields"}, nil, "file_id", "comment_id", "reply_id"),
		writeOp("files.drive.replies.create", "Create a reply to a file comment", domain.RiskWrite, http.MethodPost, "/drive/v3/files/{file_id}/comments/{comment_id}/replies", map[string]string{"fields": "fields"}, nil, "file_id", "comment_id"),
		writeOp("files.drive.replies.update", "Update a reply to a file comment", domain.RiskWrite, http.MethodPatch, "/drive/v3/files/{file_id}/comments/{comment_id}/replies/{reply_id}", map[string]string{"fields": "fields"}, nil, "file_id", "comment_id", "reply_id"),
		writeOp("files.drive.replies.delete", "Delete a reply to a file comment", domain.RiskDestructive, http.MethodDelete, "/drive/v3/files/{file_id}/comments/{comment_id}/replies/{reply_id}", nil, nil, "file_id", "comment_id", "reply_id").withoutRetry(),
		getOp("files.drive.revisions.list", "List file revisions", "/drive/v3/files/{file_id}/revisions", map[string]string{"page_size": "pageSize", "page_token": "pageToken", "fields": "fields"}, nil, "file_id"),
		getOp("files.drive.revisions.get", "Read one revision", "/drive/v3/files/{file_id}/revisions/{revision_id}", map[string]string{"acknowledge_abuse": "acknowledgeAbuse", "fields": "fields"}, nil, "file_id", "revision_id"),
		writeOp("files.drive.revisions.update", "Update revision metadata", domain.RiskWrite, http.MethodPatch, "/drive/v3/files/{file_id}/revisions/{revision_id}", map[string]string{"fields": "fields"}, nil, "file_id", "revision_id"),
		writeOp("files.drive.revisions.delete", "Delete a file revision", domain.RiskDestructive, http.MethodDelete, "/drive/v3/files/{file_id}/revisions/{revision_id}", nil, nil, "file_id", "revision_id").withoutRetry(),
		getOp("files.drive.shared_drives.list", "List shared drives", "/drive/v3/drives", map[string]string{"page_size": "pageSize", "page_token": "pageToken", "query": "q", "use_domain_admin_access": "useDomainAdminAccess"}, nil),
		getOp("files.drive.shared_drives.get", "Read one shared drive", "/drive/v3/drives/{drive_id}", map[string]string{"use_domain_admin_access": "useDomainAdminAccess"}, nil, "drive_id"),
		writeOp("files.drive.shared_drives.create", "Create a shared drive", domain.RiskWrite, http.MethodPost, "/drive/v3/drives", map[string]string{"request_id": "requestId"}, nil, "request_id"),
		writeOp("files.drive.shared_drives.update", "Update a shared drive", domain.RiskWrite, http.MethodPatch, "/drive/v3/drives/{drive_id}", map[string]string{"use_domain_admin_access": "useDomainAdminAccess"}, nil, "drive_id"),
		writeOp("files.drive.shared_drives.delete", "Delete a shared drive", domain.RiskDestructive, http.MethodDelete, "/drive/v3/drives/{drive_id}", map[string]string{"use_domain_admin_access": "useDomainAdminAccess"}, nil, "drive_id").withoutRetry(),
		getOp("files.drive.changes.start_page_token", "Get the starting changes cursor", "/drive/v3/changes/startPageToken", map[string]string{"drive_id": "driveId", "supports_all_drives": "supportsAllDrives"}, fileSync),
		getOp("files.drive.changes.list", "Read incremental file changes", "/drive/v3/changes", map[string]string{"page_token": "pageToken", "page_size": "pageSize", "drive_id": "driveId", "include_items_from_all_drives": "includeItemsFromAllDrives", "supports_all_drives": "supportsAllDrives", "fields": "fields"}, fileSync, "page_token"),
		writeOp("files.drive.changes.watch", "Open a Drive changes watch channel", domain.RiskWrite, http.MethodPost, "/drive/v3/changes/watch", map[string]string{"page_token": "pageToken", "drive_id": "driveId", "supports_all_drives": "supportsAllDrives"}, fileSync, "page_token"),
		writeOp("files.drive.channels.stop", "Stop a Drive watch channel", domain.RiskWrite, http.MethodPost, "/drive/v3/channels/stop", nil, nil),
		{Name: "files.drive.raw", Description: "Call a documented Google Drive v3 endpoint on the fixed Google API origin", Risk: domain.RiskRaw, Body: BodyRaw, InputSchema: rawSchema(), IdempotencyHeader: "Idempotency-Key", Retry: idempotentWriteRetry, Raw: &RawPolicy{Methods: []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete}, PathPrefixes: []string{"/drive/v3/", "/upload/drive/v3/"}}},
	}
	return Manifest{Provider: "google_drive", Capability: domain.Files, APIVersion: DriveAPIVersion, OriginKind: OriginFixed, Origin: "https://www.googleapis.com", CredentialHeader: "Authorization", CredentialScheme: "Bearer", MaxRequestBytes: defaultDriveMaxRequestBytes, MaxResponseBytes: defaultMaxResponseBytes, Operations: operations}
}

func gmailManifest() Manifest {
	historySync := &SyncSpec{
		Strategy:       "watch_history",
		CursorField:    "historyId",
		WebhookCapable: true,
		Resource:       "messages",
	}
	operations := []OperationManifest{
		{
			Name: "outreach.gmail.history.list", Description: "Read Gmail history after a durable history ID", Risk: domain.RiskRead,
			Method: http.MethodGet, Path: "/gmail/v1/users/me/history",
			Query: map[string]string{
				"start_history_id": "startHistoryId", "label_id": "labelId", "history_types": "historyTypes",
				"max_results": "maxResults", "page_token": "pageToken",
			},
			Required: []string{"start_history_id"}, Body: BodyNone, InputSchema: gmailHistorySchema(),
			Retry: readRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.messages.list", Description: "List Gmail messages using a bounded provider query", Risk: domain.RiskRead,
			Method: http.MethodGet, Path: "/gmail/v1/users/me/messages",
			Query: map[string]string{
				"query": "q", "label_ids": "labelIds", "include_spam_trash": "includeSpamTrash",
				"max_results": "maxResults", "page_token": "pageToken",
			},
			Body: BodyNone, InputSchema: gmailMessagesListSchema(), Retry: readRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.messages.get", Description: "Read one Gmail message just in time", Risk: domain.RiskRead,
			Method: http.MethodGet, Path: "/gmail/v1/users/me/messages/{message_id}",
			Query:    map[string]string{"format": "format", "metadata_headers": "metadataHeaders"},
			Required: []string{"message_id"}, Body: BodyNone, InputSchema: gmailMessageGetSchema(),
			Retry: readRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.threads.get", Description: "Read one Gmail conversation just in time", Risk: domain.RiskRead,
			Method: http.MethodGet, Path: "/gmail/v1/users/me/threads/{thread_id}",
			Query:    map[string]string{"format": "format", "metadata_headers": "metadataHeaders"},
			Required: []string{"thread_id"}, Body: BodyNone, InputSchema: gmailThreadGetSchema(),
			Retry: readRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.attachments.get", Description: "Read one Gmail attachment just in time", Risk: domain.RiskRead,
			Method: http.MethodGet, Path: "/gmail/v1/users/me/messages/{message_id}/attachments/{attachment_id}",
			Required: []string{"message_id", "attachment_id"}, Body: BodyNone,
			InputSchema: gmailAttachmentGetSchema(), Retry: readRetry,
		},
		{
			Name: "outreach.gmail.watch", Description: "Renew the Gmail Pub/Sub watch for the configured project topic", Risk: domain.RiskWrite,
			Method: http.MethodPost, Path: "/gmail/v1/users/me/watch",
			Required: []string{"body"}, Body: BodyJSON, InputSchema: gmailWatchSchema(),
			Retry: noRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.drafts.create", Description: "Create an unpublished Gmail draft", Risk: domain.RiskDraft,
			Method: http.MethodPost, Path: "/gmail/v1/users/me/drafts",
			Required: []string{"body"}, Body: BodyJSON, InputSchema: gmailDraftCreateSchema(),
			Retry: noRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.drafts.send", Description: "Send a previously created Gmail draft", Risk: domain.RiskPublish,
			Method: http.MethodPost, Path: "/gmail/v1/users/me/drafts/send",
			Required: []string{"body"}, Body: BodyJSON, InputSchema: gmailDraftSendSchema(),
			Retry: noRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.messages.send", Description: "Send a bounded RFC 2822 Gmail message", Risk: domain.RiskPublish,
			Method: http.MethodPost, Path: "/gmail/v1/users/me/messages/send",
			Required: []string{"body"}, Body: BodyJSON, InputSchema: gmailMessageSendSchema(),
			Retry: noRetry, Sync: historySync,
		},
		{
			Name: "outreach.gmail.raw", Description: "Read Gmail history or messages on the fixed Google API origin", Risk: domain.RiskRaw,
			Body: BodyRaw, InputSchema: rawSchema(), Retry: readRetry,
			Raw: &RawPolicy{
				Methods: []string{http.MethodGet},
				PathPrefixes: []string{
					"/gmail/v1/users/me/history",
					"/gmail/v1/users/me/messages",
				},
			},
		},
	}
	return Manifest{
		Provider: "gmail", Capability: domain.Outreach, APIVersion: "v1",
		OriginKind: OriginFixed, Origin: "https://www.googleapis.com",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
		MaxRequestBytes: defaultGmailRequestBytes, MaxResponseBytes: 36 << 20,
		Operations: operations,
	}
}

func postizManifest() Manifest {
	socialSync := &SyncSpec{Strategy: "incremental_poll", CursorField: "next", Resource: "posts"}
	operations := []OperationManifest{
		getOp("social.postiz.integrations.list", "List connected social integrations", "/public/v1/integrations", nil, &SyncSpec{Strategy: "incremental_poll", CursorField: "next", Resource: "integrations"}),
		getOp("social.postiz.posts.list", "List posts, drafts, and scheduled publications", "/public/v1/posts", map[string]string{"start_date": "startDate", "end_date": "endDate", "customer": "customer"}, socialSync, "start_date", "end_date"),
		writeOp("social.postiz.posts.create", "Create or schedule a post", domain.RiskPublish, http.MethodPost, "/public/v1/posts", nil, socialSync, "type", "date", "shortLink", "tags"),
		writeOp("social.postiz.posts.delete", "Delete a draft or scheduled post", domain.RiskDestructive, http.MethodDelete, "/public/v1/posts/{post_id}", nil, socialSync, "post_id").withoutRetry(),
		writeOp("social.postiz.posts.status.update", "Change a post publication status", domain.RiskPublish, http.MethodPut, "/public/v1/posts/{post_id}/status", nil, socialSync, "post_id", "status"),
		writeOp("social.postiz.posts.release_id.update", "Update a post provider release identifier", domain.RiskWrite, http.MethodPut, "/public/v1/posts/{post_id}/release-id", nil, socialSync, "post_id", "releaseId"),
		getOp("social.postiz.posts.missing", "Read missing content for a post", "/public/v1/posts/{post_id}/missing", nil, socialSync, "post_id"),
		writeOp("social.postiz.drafts.create", "Create an unpublished social draft", domain.RiskDraft, http.MethodPost, "/public/v1/posts", nil, socialSync, "type", "date", "shortLink", "tags"),
		writeOp("social.postiz.media.upload", "Upload media from base64", domain.RiskWrite, http.MethodPost, "/public/v1/upload", nil, nil, "content_base64", "mime_type").withBody(BodyMultipartBase64),
		getOp("social.postiz.analytics.posts", "Read analytics for a published post", "/public/v1/analytics/post/{post_id}", map[string]string{"date": "date"}, &SyncSpec{Strategy: "snapshot", Resource: "analytics"}, "post_id", "date"),
		{Name: "social.postiz.raw", Description: "Call a documented Postiz Public API endpoint on the fixed API version", Risk: domain.RiskRaw, Body: BodyRaw, InputSchema: rawSchema(), IdempotencyHeader: "Idempotency-Key", Retry: idempotentWriteRetry, Raw: &RawPolicy{Methods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}, PathPrefixes: []string{"/public/v1/"}}},
	}
	return Manifest{Provider: "postiz", Capability: domain.Social, APIVersion: PostizAPIVersion, OriginKind: OriginFixed, Origin: "https://api.postiz.com", CredentialHeader: "Authorization", CredentialScheme: "", MaxRequestBytes: defaultMaxRequestBytes, MaxResponseBytes: defaultMaxResponseBytes, Operations: operations}
}

func pipeboardManifest() Manifest {
	adsSync := &SyncSpec{Strategy: "incremental_poll", CursorField: "next_cursor", Resource: "ads"}
	actions := func(meta, google string) map[string]string {
		result := map[string]string{}
		if meta != "" {
			result["meta_ads"] = meta
		}
		if google != "" {
			result["google_ads"] = google
		}
		return result
	}
	rpc := func(name, description string, endpointActions map[string]string, risk domain.Risk, sync *SyncSpec) OperationManifest {
		// The hosted free plan counts tool executions, not logical OpenAgent
		// invocations. Keep exactly one upstream request per durable reservation;
		// Pipeboard already handles Meta/Google retries internally.
		return OperationManifest{Name: name, Description: description, Risk: risk, Method: http.MethodPost, Path: "/", Body: BodyRPC, RPCActions: endpointActions, InputSchema: typedSchema(), IdempotencyHeader: "Idempotency-Key", Retry: noRetry, Sync: sync}
	}
	operations := []OperationManifest{
		rpc("ads.pipeboard.accounts.list", "List connected Meta or Google Ads accounts", actions("get_ad_accounts", "list_google_ads_customers"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.campaigns.list", "List campaigns with status and performance", actions("get_campaigns", "get_google_ads_campaigns"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.campaigns.get", "Read campaign details", actions("get_campaign_details", "get_google_ads_campaigns"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.campaigns.create", "Create a paused campaign", actions("create_campaign", "create_google_ads_campaign"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.campaigns.update", "Update campaign settings", actions("update_campaign", "update_google_ads_campaign"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.campaigns.enable", "Enable a paused campaign", actions("update_campaign", "enable_google_ads_campaign"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.campaigns.pause", "Pause a campaign", actions("update_campaign", "pause_google_ads_campaign"), domain.RiskWrite, adsSync),
		rpc("ads.pipeboard.ad_groups.list", "List ad sets or ad groups", actions("get_adsets", "get_google_ads_ad_groups"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.ad_groups.create", "Create an ad set or ad group", actions("create_adset", "create_google_ads_ad_group"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.ad_groups.update", "Update an ad set or ad group", actions("update_adset", "update_google_ads_ad_group"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.ads.list", "List ads", actions("get_ads", "get_google_ads_ads"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.ads.create", "Create an ad", actions("create_ad", "create_google_ads_responsive_search_ad"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.ads.update", "Update or pause an ad", actions("update_ad", "pause_google_ads_ad"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.creatives.list", "List ad creatives", actions("get_ad_creatives", "get_google_ads_ads"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.creatives.create", "Create an ad creative", actions("create_ad_creative", "create_google_ads_responsive_search_ad"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.budgets.update", "Change campaign or ad-group budget", actions("update_campaign", "update_google_ads_campaign"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.bids.update", "Change ad-set or keyword bidding", actions("update_adset", "update_google_ads_keyword_bid"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.keywords.list", "List Google Ads keywords", actions("", "get_google_ads_keywords"), domain.RiskRead, adsSync),
		rpc("ads.pipeboard.keywords.update", "Add or update Google Ads keywords", actions("", "add_google_ads_keywords"), domain.RiskSpend, adsSync),
		rpc("ads.pipeboard.reports.run", "Run an ads performance report", actions("get_insights", "get_google_ads_campaign_metrics"), domain.RiskRead, &SyncSpec{Strategy: "incremental_poll", CursorField: "next_cursor", Resource: "reports"}),
		rpc("ads.pipeboard.google.gaql", "Execute a Google Ads GAQL report", actions("", "execute_google_ads_gaql_query"), domain.RiskRead, &SyncSpec{Strategy: "incremental_poll", CursorField: "next_cursor", Resource: "reports"}),
		rpc("ads.pipeboard.meta.bulk_insights", "Read insights across Meta ad accounts", actions("bulk_get_insights", ""), domain.RiskRead, &SyncSpec{Strategy: "incremental_poll", CursorField: "next_cursor", Resource: "reports"}),
		{Name: "ads.pipeboard.raw", Description: "Call Pipeboard tools/list or tools/call on the configured ads MCP endpoint", Risk: domain.RiskRaw, Body: BodyRaw, InputSchema: rawSchema(), IdempotencyHeader: "Idempotency-Key", Retry: noRetry, Raw: &RawPolicy{Methods: []string{http.MethodPost}, PathPrefixes: []string{"/"}}},
	}
	return Manifest{Provider: "pipeboard", Capability: domain.Ads, APIVersion: PipeboardVersion, OriginKind: OriginPipeboard, CredentialHeader: "Authorization", CredentialScheme: "Bearer", MaxRequestBytes: defaultMaxRequestBytes, MaxResponseBytes: defaultMaxResponseBytes, Operations: operations}
}

func getOp(name, description, path string, query map[string]string, sync *SyncSpec, required ...string) OperationManifest {
	return OperationManifest{Name: name, Description: description, Risk: domain.RiskRead, Method: http.MethodGet, Path: path, Query: query, Required: required, Body: BodyNone, InputSchema: typedSchema(required...), Retry: readRetry, Sync: sync}
}

func writeOp(name, description string, risk domain.Risk, method, path string, query map[string]string, sync *SyncSpec, required ...string) OperationManifest {
	return OperationManifest{Name: name, Description: description, Risk: risk, Method: method, Path: path, Query: query, Required: required, Body: BodyJSON, InputSchema: typedSchema(required...), IdempotencyHeader: "Idempotency-Key", Retry: idempotentWriteRetry, Sync: sync}
}

func (operation OperationManifest) withFixedQuery(key, value string) OperationManifest {
	if operation.FixedQuery == nil {
		operation.FixedQuery = make(map[string]string)
	}
	operation.FixedQuery[key] = value
	return operation
}

func (operation OperationManifest) withBody(body BodyMode) OperationManifest {
	operation.Body = body
	return operation
}

func (operation OperationManifest) withGraphQLIdempotency(variable string) OperationManifest {
	operation.GraphQLIdempotencyVariable = variable
	return operation
}

func (operation OperationManifest) withRequiredScopes(scopes ...string) OperationManifest {
	operation.RequiredScopes = append([]string(nil), scopes...)
	return operation
}

func (operation OperationManifest) internalOnly() OperationManifest {
	operation.InternalOnly = true
	return operation
}

func (operation OperationManifest) withoutRetry() OperationManifest {
	operation.Retry = noRetry
	return operation
}

func typedSchema(required ...string) json.RawMessage {
	properties := map[string]any{
		"connection_id":  map[string]any{"type": "string", "description": "OpenAgent connection identifier"},
		"provider":       map[string]any{"type": "string", "description": "Optional provider discriminator"},
		"body":           map[string]any{"type": "object"},
		"variables":      map[string]any{"type": "object"},
		"content_base64": map[string]any{"type": "string", "contentEncoding": "base64"},
		"mime_type":      map[string]any{"type": "string"},
		"file_name":      map[string]any{"type": "string"},
		"metadata":       map[string]any{"type": "object", "description": "Provider-neutral file metadata"},
		"theme_id":       map[string]any{"type": "string", "description": "Shopify OnlineStoreTheme GraphQL ID"},
		"asset_key":      map[string]any{"type": "string", "description": "Shopify theme filename"},
		"files":          map[string]any{"type": "array", "items": map[string]any{}},
		"upload_mode":    map[string]any{"type": "string", "enum": []string{"auto", "simple", "multipart", "resumable"}},
		"type":           map[string]any{"type": "string", "enum": []string{"draft", "schedule", "now"}},
		"date":           map[string]any{"type": "string", "format": "date-time"},
		"shortLink":      map[string]any{"type": "boolean"},
		"tags":           map[string]any{"type": "array", "items": map[string]any{}},
		"posts":          map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		"status":         map[string]any{"type": "string", "enum": []string{"draft", "schedule"}},
		"releaseId":      map[string]any{"type": "string"},
	}
	for _, name := range required {
		if _, described := properties[name]; !described {
			properties[name] = map[string]any{"type": []string{"string", "number", "boolean"}}
		}
	}
	schema := map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": true}
	encoded, _ := json.Marshal(schema)
	return encoded
}

func shopifyProductVariantsSchema() json.RawMessage {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"connection_id": map[string]any{"type": "string", "description": "OpenAgent connection identifier"},
			"provider":      map[string]any{"type": "string", "enum": []string{"shopify"}},
			"product_id": map[string]any{
				"type":        "string",
				"description": "Shopify Product GraphQL GID returned by products.list/get, or its numeric ID",
				"pattern":     `^(?:gid://shopify/Product/)?[1-9][0-9]*$`,
			},
			"first": map[string]any{"type": "integer", "minimum": 1, "maximum": 250, "default": 100},
			"after": map[string]any{"type": "string", "minLength": 1, "maxLength": 2048, "description": "Exact endCursor from the preceding page"},
		},
		"required":             []string{"product_id"},
		"additionalProperties": false,
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}

func driveUploadSchema(update bool) json.RawMessage {
	required := []string{"content_base64", "mime_type"}
	if update {
		required = append([]string{"file_id"}, required...)
	}
	properties := map[string]any{
		"connection_id":       map[string]any{"type": "string", "description": "OpenAgent connection identifier"},
		"provider":            map[string]any{"type": "string", "enum": []string{"google_drive"}},
		"file_id":             map[string]any{"type": "string"},
		"content_base64":      map[string]any{"type": "string", "contentEncoding": "base64", "description": "One in-memory payload, at most 16 MiB before base64 encoding"},
		"mime_type":           map[string]any{"type": "string"},
		"metadata":            map[string]any{"type": "object"},
		"upload_mode":         map[string]any{"type": "string", "enum": []string{"auto", "simple", "multipart", "resumable"}, "default": "auto"},
		"fields":              map[string]any{"type": "string"},
		"supports_all_drives": map[string]any{"type": "boolean"},
	}
	schema := map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": true}
	encoded, _ := json.Marshal(schema)
	return encoded
}

func rawSchema() json.RawMessage {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"connection_id": map[string]any{"type": "string"},
			"provider":      map[string]any{"type": "string"},
			"method":        map[string]any{"type": "string", "enum": []string{"GET", "POST", "PUT", "PATCH", "DELETE"}},
			"path":          map[string]any{"type": "string", "description": "Provider-relative path within the manifest allowlist; never a URL"},
			"query":         map[string]any{"type": "object", "additionalProperties": map[string]any{"type": []string{"string", "number", "boolean", "array"}}},
			"body":          map[string]any{},
		},
		"required": []string{"method", "path"}, "additionalProperties": false,
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}
