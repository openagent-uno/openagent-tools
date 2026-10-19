package connectors

import (
	"encoding/json"
	"github.com/openagent-uno/openagent-tools/packages/connectors/providers"
)

const Version = "0.1.12"

type Item struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Category          string   `json:"category"`
	Auth              string   `json:"auth"`
	Icon              string   `json:"icon"`
	LogoSVG           string   `json:"logoSvg,omitempty"`
	SetupURL          string   `json:"setupUrl,omitempty"`
	SetupInstructions string   `json:"setupInstructions,omitempty"`
	Capability        string   `json:"capability"`
	Provider          string   `json:"provider"`
	ReadTools         []string `json:"readTools"`
	AgentTools        []string `json:"agentTools"`
	Available         bool     `json:"available"`
	UnavailableReason string   `json:"unavailableReason,omitempty"`
}
type CatalogEntry struct {
	Item
	NativeKind string `json:"nativeKind,omitempty"`
}

var catalogEntries = []CatalogEntry{
	{Item: Item{
		ID: "onedrive", Name: "OneDrive", Description: "Read existing account drives and host-bound file metadata or bounded file contents. No file mutations or automatic drive provisioning.",
		Category: "Productivity", Auth: "oauth", Icon: "cloud", Capability: "files", Provider: "onedrive",
		ReadTools: []string{"files.onedrive.drives.list", "files.onedrive.drives.get", "files.onedrive.items.list", "files.onedrive.items.get", "files.onedrive.items.content"}, AgentTools: []string{},
	}},
	{Item: Item{
		ID: "sharepoint", Name: "SharePoint", Description: "Find authorized sites and read host-bound document libraries, file metadata and bounded contents using explicit delegated Sites.Read.All consent.",
		Category: "Productivity", Auth: "oauth", Icon: "files", Capability: "files", Provider: "sharepoint",
		ReadTools: []string{"files.sharepoint.sites.search", "files.sharepoint.sites.get", "files.sharepoint.drives.list", "files.sharepoint.drives.get", "files.sharepoint.items.list", "files.sharepoint.items.get", "files.sharepoint.items.content"}, AgentTools: []string{},
	}},

	{Item: Item{
		ID: "google-calendar", Name: "Google Calendar", Description: "Read calendars and events across connected Google accounts, and create, update or delete authorized events with version checks.",
		Category: "Productivity", Auth: "oauth", Icon: "calendar", Capability: "files", Provider: "google_calendar",
		ReadTools:  []string{"files.google_calendar.calendars.list", "files.google_calendar.calendars.get", "files.google_calendar.events.list", "files.google_calendar.events.get"},
		AgentTools: []string{"files.google_calendar.events.create", "files.google_calendar.events.update", "files.google_calendar.events.delete"},
	}},
	{Item: Item{
		ID: "outlook-mail", Name: "Outlook Mail", Description: "Read Microsoft mail folders, messages and attachments, prepare drafts, and send with separate authorization.",
		Category: "Communication", Auth: "oauth", Icon: "mail", Capability: "outreach", Provider: "outlook_mail",
		ReadTools:  []string{"outreach.outlook_mail.folders.list", "outreach.outlook_mail.folders.get", "outreach.outlook_mail.messages.list", "outreach.outlook_mail.messages.get", "outreach.outlook_mail.attachments.list", "outreach.outlook_mail.attachments.get"},
		AgentTools: []string{"outreach.outlook_mail.drafts.create", "outreach.outlook_mail.drafts.update", "outreach.outlook_mail.messages.send"},
	}},
	{Item: Item{
		ID: "outlook-calendar", Name: "Outlook Calendar", Description: "Read Microsoft calendars and events, and create or edit authorized UTC events. This initial subset does not expand recurrence or invite attendees.",
		Category: "Productivity", Auth: "oauth", Icon: "calendar", Capability: "files", Provider: "outlook_calendar",
		ReadTools:  []string{"files.outlook_calendar.calendars.list", "files.outlook_calendar.calendars.get", "files.outlook_calendar.events.list", "files.outlook_calendar.events.get"},
		AgentTools: []string{"files.outlook_calendar.events.create", "files.outlook_calendar.events.update", "files.outlook_calendar.events.delete"},
	}},
	{Item: Item{
		ID: "coingecko", Name: "CoinGecko", Description: "Read public cryptocurrency prices and global market aggregates through fixed, read-only MCP operations. Provider free-use limits apply.",
		Category: "Data", Auth: "none", Icon: "bar-chart-2", Capability: "files", Provider: "coingecko",
		ReadTools: []string{"files.coingecko.price", "files.coingecko.global"}, AgentTools: []string{},
	}},
	{Item: Item{
		ID: "context7", Name: "Context7", Description: "Find public library documentation and code examples through Context7's anonymous MCP service. Provider free-use limits apply.",
		Category: "Developer", Auth: "none", Icon: "book-open", Capability: "files", Provider: "context7",
		ReadTools: []string{"files.context7.resolve_library", "files.context7.query_docs"}, AgentTools: []string{},
	}},
	{Item: Item{
		ID: "parallel-search", Name: "Parallel Search", Description: "Search the public web and read page excerpts through Parallel's anonymous MCP service. Provider free-use limits apply.",
		Category: "Data", Auth: "none", Icon: "search", Capability: "files", Provider: "parallel_search",
		ReadTools: []string{"files.parallel.search", "files.parallel.fetch"}, AgentTools: []string{},
	}},
	{Item: Item{
		ID: "exa", Name: "Exa", Description: "Search the public web and fetch page content through Exa's keyless MCP service. Provider free-use limits apply.",
		Category: "Data", Auth: "none", Icon: "search", Capability: "files", Provider: "exa",
		ReadTools: []string{"files.exa.search", "files.exa.fetch"}, AgentTools: []string{},
	}},
	{Item: Item{
		ID: "firecrawl", Name: "Firecrawl", Description: "Search the public web and read pages as Markdown through Firecrawl's keyless MCP service. Provider free-use limits apply.",
		Category: "Data", Auth: "none", Icon: "flame", Capability: "files", Provider: "firecrawl",
		ReadTools: []string{"files.firecrawl.search", "files.firecrawl.scrape"}, AgentTools: []string{},
	}},
	{Item: Item{
		ID: "google-drive", Name: "Google Drive", Description: "Search, read and manage files in Google Drive.",
		Category: "Productivity", Auth: "oauth", Icon: "hard-drive", Capability: "files", Provider: "google_drive",
		ReadTools:  []string{"files.drive.search", "files.drive.files.get", "files.drive.files.download"},
		AgentTools: []string{"files.drive.files.content.create", "files.drive.files.content.update"},
	}},
	{Item: Item{
		ID: "github", Name: "GitHub", Description: "Browse repositories, issues and pull requests.",
		Category: "Developer", Auth: "oauth", Icon: "github", Capability: "files", Provider: "github",
		ReadTools: []string{"files.github.user.get", "files.github.repositories.list", "files.github.repositories.user.list", "files.github.repositories.get",
			"files.github.repositories.branches.list", "files.github.git.commits.get", "files.github.git.trees.get", "files.github.git.blobs.get",
			"files.github.issues.list", "files.github.issues.get", "files.github.issue_comments.list",
			"files.github.pulls.list", "files.github.pulls.get", "files.github.pulls.files.list"},
		AgentTools: []string{"files.github.issues.create", "files.github.issues.update", "files.github.issue_comments.create"},
	}},
	{Item: Item{
		ID: "notion", Name: "Notion", Description: "Search shared pages and data sources, read pages and blocks, and create or edit authorized content.",
		Category: "Productivity", Auth: "oauth", Icon: "notion", Capability: "files", Provider: "notion",
		ReadTools:  []string{"files.notion.search", "files.notion.pages.get", "files.notion.blocks.children.list", "files.notion.users.get", "files.notion.users.list"},
		AgentTools: []string{"files.notion.pages.create", "files.notion.pages.update", "files.notion.blocks.children.append"},
	}},
	{Item: Item{
		ID: "atlassian", Name: "Atlassian", Description: "Read Jira projects, issues and comments, and create or edit authorized issues and comments on a selected site.",
		Category: "Productivity", Auth: "oauth", Icon: "atlassian", Capability: "files", Provider: "atlassian",
		ReadTools:  []string{"files.atlassian.resources.list", "files.atlassian.projects.list", "files.atlassian.projects.get", "files.atlassian.issues.search", "files.atlassian.issues.get", "files.atlassian.issue_comments.list"},
		AgentTools: []string{"files.atlassian.issues.create", "files.atlassian.issues.update", "files.atlassian.issue_comments.create"},
	}},
	{Item: Item{
		ID: "slack-import", Name: "Slack", Description: "Read authorized Slack conversations and user information, and post, edit or delete authorized messages.",
		Category: "Communication", Auth: "oauth", Icon: "message-square", Capability: "social", Provider: "slack_import",
		ReadTools:  []string{"social.slack_import.auth.test", "social.slack_import.conversations.list", "social.slack_import.conversations.info", "social.slack_import.conversations.history", "social.slack_import.conversations.replies", "social.slack_import.users.info"},
		AgentTools: []string{"social.slack_import.chat.post_message", "social.slack_import.chat.update", "social.slack_import.chat.delete"},
	}},
	{Item: Item{
		ID: "gmail", Name: "Gmail", Description: "Read email and let authorized agents prepare drafts or send messages.",
		Category: "Communication", Auth: "oauth", Icon: "mail", Capability: "outreach", Provider: "gmail",
		ReadTools:  []string{"outreach.gmail.messages.list", "outreach.gmail.messages.get", "outreach.gmail.threads.get", "outreach.gmail.attachments.get"},
		AgentTools: []string{"outreach.gmail.drafts.create", "outreach.gmail.drafts.send", "outreach.gmail.messages.send"},
	}},
	{Item: Item{
		ID: "postiz", Name: "Postiz", Description: "Read social channels and analytics, and prepare or schedule social posts.",
		Category: "Social", Auth: "oauth", Icon: "share-2", Capability: "social", Provider: "postiz",
		ReadTools:  []string{"social.postiz.integrations.list", "social.postiz.posts.list", "social.postiz.analytics.posts"},
		AgentTools: []string{"social.postiz.drafts.create", "social.postiz.posts.create", "social.postiz.media.upload"},
	}},
	{Item: Item{
		ID: "pipeboard", Name: "Pipeboard Ads", Description: "Read Meta and Google Ads campaigns and reports, with agent access to pause campaigns.",
		Category: "Ads", Auth: "token", Icon: "bar-chart-2", Capability: "ads", Provider: "pipeboard",
		ReadTools:  []string{"ads.pipeboard.accounts.list", "ads.pipeboard.campaigns.list", "ads.pipeboard.campaigns.get", "ads.pipeboard.reports.run"},
		AgentTools: []string{"ads.pipeboard.campaigns.pause"},
	}},
	{Item: Item{
		ID: "shopify", Name: "Shopify", Description: "Read and manage products, orders and store operations.",
		Category: "Commerce", Auth: "oauth", Icon: "shopping-bag", Capability: "commerce", Provider: "shopify",
		ReadTools:  []string{"commerce.shopify.products.list", "commerce.shopify.orders.list"},
		AgentTools: []string{"commerce.shopify.products.update", "commerce.shopify.orders.cancel"},
	}},
	{Item: Item{
		ID: "replio", Name: "Replio", Description: "Read your organization's apps, conversations and support statistics.",
		Category: "Communication", Auth: "token", Icon: "message-circle", Capability: "outreach", Provider: "replio",
		ReadTools:  []string{"outreach.replio.apps.list", "outreach.replio.threads.list", "outreach.replio.threads.get", "outreach.replio.stats.overview"},
		AgentTools: []string{},
	}},
	{Item: Item{
		ID: "billingbear", Name: "BillingBear", Description: "Read project revenue and customer billing statistics and history.",
		Category: "Commerce", Auth: "token", Icon: "credit-card", Capability: "commerce", Provider: "billingbear",
		ReadTools:  []string{"commerce.billingbear.project.stats", "commerce.billingbear.customers.stats", "commerce.billingbear.customers.history"},
		AgentTools: []string{},
	}},
	{Item: Item{
		ID: "google-analytics", Name: "Google Analytics", Description: "Explore GA4 properties, reports and realtime analytics with read-only Google access.",
		Category: "Data", Auth: "oauth", Icon: "trending-up", Capability: "ads", Provider: "google_analytics",
		ReadTools:  []string{"ads.google_analytics.account_summaries.list", "ads.google_analytics.reports.run", "ads.google_analytics.realtime.run", "ads.google_analytics.metadata.get"},
		AgentTools: []string{},
	}},
	{Item: Item{
		ID: "clickup", Name: "ClickUp", Description: "Read and manage tasks, Lists, Folders, Spaces, comments, Docs, Goals and time tracking in your ClickUp Workspaces.",
		Category: "Productivity", Auth: "oauth", Icon: "check-square", Capability: "files", Provider: "clickup",
		ReadTools: []string{
			"files.clickup.user.get", "files.clickup.workspaces.list", "files.clickup.spaces.list", "files.clickup.spaces.get",
			"files.clickup.folders.list", "files.clickup.folders.get", "files.clickup.lists.list", "files.clickup.lists.list_folderless", "files.clickup.lists.get",
			"files.clickup.shared_hierarchy.get", "files.clickup.custom_task_types.list", "files.clickup.groups.list",
			"files.clickup.tasks.list", "files.clickup.tasks.search", "files.clickup.tasks.get", "files.clickup.task_templates.list",
			"files.clickup.task_members.list", "files.clickup.list_members.list", "files.clickup.view_tasks.list", "files.clickup.views.list", "files.clickup.list_views.list",
			"files.clickup.comments.list", "files.clickup.list_comments.list", "files.clickup.comment_replies.list",
			"files.clickup.tags.list", "files.clickup.custom_fields.list", "files.clickup.goals.list", "files.clickup.goals.get",
			"files.clickup.time_entries.list", "files.clickup.time_entries.get", "files.clickup.time_entries.current",
			"files.clickup.docs.list", "files.clickup.docs.get", "files.clickup.doc_pages.list", "files.clickup.doc_pages.get",
			"files.clickup.chat_channels.list", "files.clickup.chat_messages.list", "files.clickup.webhooks.list",
		},
		AgentTools: []string{
			"files.clickup.tasks.create", "files.clickup.tasks.update", "files.clickup.tasks.delete", "files.clickup.tasks.create_from_template",
			"files.clickup.comments.create", "files.clickup.list_comments.create", "files.clickup.comment_replies.create", "files.clickup.comments.update", "files.clickup.comments.delete",
			"files.clickup.tags.create", "files.clickup.tags.add", "files.clickup.tags.remove", "files.clickup.custom_fields.set", "files.clickup.custom_fields.remove",
			"files.clickup.checklists.create", "files.clickup.checklists.update", "files.clickup.checklists.delete",
			"files.clickup.checklist_items.create", "files.clickup.checklist_items.update", "files.clickup.checklist_items.delete",
			"files.clickup.dependencies.add", "files.clickup.dependencies.remove", "files.clickup.links.add", "files.clickup.links.remove",
			"files.clickup.lists.create", "files.clickup.lists.create_folderless", "files.clickup.lists.update", "files.clickup.lists.delete",
			"files.clickup.folders.create", "files.clickup.folders.update", "files.clickup.folders.delete",
			"files.clickup.spaces.create", "files.clickup.spaces.update", "files.clickup.spaces.delete",
			"files.clickup.goals.create", "files.clickup.goals.update", "files.clickup.goals.delete",
			"files.clickup.key_results.create", "files.clickup.key_results.update", "files.clickup.key_results.delete",
			"files.clickup.time_entries.create", "files.clickup.time_entries.update", "files.clickup.time_entries.delete", "files.clickup.time_entries.start", "files.clickup.time_entries.stop",
			"files.clickup.docs.create", "files.clickup.doc_pages.create", "files.clickup.doc_pages.update", "files.clickup.chat_messages.create",
		},
	}},
	{Item: Item{
		ID: "imap_smtp", Name: "IMAP Email", Description: "Read email on demand and send via SMTP over TLS, with explicit agent permissions.",
		Category: "Communication", Auth: "credentials", Icon: "inbox", Capability: "outreach", Provider: "imap_smtp",
		ReadTools:  []string{"outreach.imap.mailboxes.list", "outreach.imap.messages.list", "outreach.imap.messages.get"},
		AgentTools: []string{"outreach.imap.messages.send"},
	}},
	{Item: Item{
		ID: "custom-mcp", Name: "Custom MCP", Description: "Connect a reviewed public HTTPS MCP endpoint.",
		Category: "Custom", Auth: "custom_mcp", Icon: "tool", Capability: "files", Provider: "custom_mcp",
		ReadTools: []string{}, AgentTools: []string{},
	}, NativeKind: "custom_mcp"},
}

// Catalog returns a deep copy; hosts cannot mutate the shared authorization descriptor.
func Catalog() []CatalogEntry {
	data, _ := json.Marshal(catalogEntries)
	var result []CatalogEntry
	_ = json.Unmarshal(data, &result)
	if extra, err := providers.ReviewedBatchCatalog(); err == nil {
		seen := map[string]bool{}
		for _, item := range result {
			seen[item.ID] = true
		}
		for _, item := range extra {
			if seen[item.ID] {
				continue
			}
			seen[item.ID] = true
			result = append(result, CatalogEntry{Item: Item{ID: item.ID, Name: item.Name, Description: item.Description, Category: item.Category, Auth: item.Auth, Icon: item.Icon, SetupURL: item.SetupURL, SetupInstructions: item.SetupInstructions, Capability: item.Capability, Provider: item.Provider, ReadTools: item.ReadTools, AgentTools: []string{}, Available: true}})
		}
	}
	for i := range result {
		item := &result[i]
		item.LogoSVG = Brandmark(item.Provider)
		item.Available = len(item.ReadTools)+len(item.AgentTools) > 0 || item.NativeKind == "custom_mcp"
		if !item.Available {
			item.UnavailableReason = "No reviewed tool implementation"
		}
	}
	return result
}
func Lookup(id string) (CatalogEntry, bool) {
	for _, item := range Catalog() {
		if item.ID == id {
			return item, true
		}
	}
	return CatalogEntry{}, false
}
