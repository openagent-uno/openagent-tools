package providers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/openagent-uno/openagent-tools/packages/connectors/domain"
)

const (
	clickupOrigin     = "https://api.clickup.com"
	clickupAPIVersion = "v2"
	// One JSON document per call; ClickUp bodies are small task, list or doc
	// payloads and never file uploads (attachments stay outside the manifest).
	clickupMaxRequestBytes = int64(4 << 20)
)

var (
	// ClickUp identifiers are numeric (Workspace, Space, Folder, List, comment,
	// timer), short alphanumerics (task, view, template), UUIDs (goal, key
	// result, checklist, custom field) or dash-joined tokens (doc, page,
	// channel). Custom task ids such as PROJ-12 also match. The pattern excludes
	// path separators, percent escapes, whitespace and control characters, so a
	// value can only fill its own path slot.
	clickupIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~:@+-]{0,127}$`)
	clickupTextValue = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,128}$`)
	clickupNumericID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	clickupListArgs  = map[string]bool{
		"statuses": true, "assignees": true, "watchers": true, "tags": true,
		"space_ids": true, "project_ids": true, "list_ids": true, "custom_items": true,
	}
)

// clickupOperation is compact manifest data. Method, path and origin are
// fixed here; arguments only fill named path slots, named query keys and,
// for writes, one JSON body forwarded to the documented endpoint.
type clickupOperation struct {
	name, description, method, path string
	risk                            domain.Risk
	query                           []string
	body                            string
}

const (
	clickupTaskBody       = "ClickUp task fields: name, description or markdown_content, assignees (user ids), tags, status, priority (1 urgent to 4 low), due_date and start_date (ms timestamps) with due_date_time/start_date_time, time_estimate (ms), notify_all, parent (task id for a subtask), links_to, custom_fields [{id, value}], check_required_custom_fields"
	clickupTaskUpdateBody = "ClickUp task fields to change: name, description, status, priority, due_date, start_date, time_estimate, archived, parent, assignees {add:[user ids], rem:[user ids]}, watchers {add, rem}, custom_item_id"
	clickupListBody       = "ClickUp List fields: name (required), content, markdown_content, due_date, due_date_time, priority, assignee, status"
	clickupCommentBody    = "comment_text (required), assignee (user id), notify_all"
	clickupDocBody        = "name (required), parent {id, type: 4 Space, 5 Folder, 6 List, 7 Everything, 12 Workspace}, visibility (PUBLIC or PRIVATE), create_page"
	clickupPageBody       = "name, sub_title, content, content_format (text/md or text/plain), parent_page_id"
)

var clickupOperations = []clickupOperation{
	// Identity and hierarchy.
	{name: "files.clickup.user.get", description: "Read the ClickUp user that authorized this connection", method: http.MethodGet, path: "/api/v2/user", risk: domain.RiskRead},
	{name: "files.clickup.workspaces.list", description: "List the ClickUp Workspaces (teams) this connection is authorized for, with their members; use a team id as team_id or workspace_id in every other operation", method: http.MethodGet, path: "/api/v2/team", risk: domain.RiskRead},
	{name: "files.clickup.spaces.list", description: "List the Spaces of a Workspace with their statuses and enabled features", method: http.MethodGet, path: "/api/v2/team/{team_id}/space", risk: domain.RiskRead, query: []string{"archived"}},
	{name: "files.clickup.spaces.get", description: "Read one Space with its statuses and features", method: http.MethodGet, path: "/api/v2/space/{space_id}", risk: domain.RiskRead},
	{name: "files.clickup.folders.list", description: "List the Folders of a Space with the Lists inside each Folder", method: http.MethodGet, path: "/api/v2/space/{space_id}/folder", risk: domain.RiskRead, query: []string{"archived"}},
	{name: "files.clickup.folders.get", description: "Read one Folder and its Lists", method: http.MethodGet, path: "/api/v2/folder/{folder_id}", risk: domain.RiskRead},
	{name: "files.clickup.lists.list", description: "List the Lists inside a Folder", method: http.MethodGet, path: "/api/v2/folder/{folder_id}/list", risk: domain.RiskRead, query: []string{"archived"}},
	{name: "files.clickup.lists.list_folderless", description: "List the Lists of a Space that are not inside a Folder", method: http.MethodGet, path: "/api/v2/space/{space_id}/list", risk: domain.RiskRead, query: []string{"archived"}},
	{name: "files.clickup.lists.get", description: "Read one List with its statuses, assignee and task count", method: http.MethodGet, path: "/api/v2/list/{list_id}", risk: domain.RiskRead},
	{name: "files.clickup.shared_hierarchy.get", description: "Read the tasks, Lists and Folders shared with the authorized user outside their normal hierarchy", method: http.MethodGet, path: "/api/v2/team/{team_id}/shared", risk: domain.RiskRead},
	{name: "files.clickup.custom_task_types.list", description: "List the custom task types of a Workspace", method: http.MethodGet, path: "/api/v2/team/{team_id}/custom_item", risk: domain.RiskRead},
	{name: "files.clickup.groups.list", description: "List the user groups (Teams) of a Workspace", method: http.MethodGet, path: "/api/v2/group", risk: domain.RiskRead, query: []string{"team_id", "group_ids"}},
	// Tasks.
	{name: "files.clickup.tasks.list", description: "List the tasks of a List, 100 per page starting at page 0; request the next page until fewer than 100 tasks return. Filter by statuses, assignees, tags, due/created/updated/done timestamps (ms) and custom_fields (JSON string)", method: http.MethodGet, path: "/api/v2/list/{list_id}/task", risk: domain.RiskRead, query: []string{"archived", "include_markdown_description", "page", "order_by", "reverse", "subtasks", "statuses", "include_closed", "assignees", "watchers", "tags", "due_date_gt", "due_date_lt", "date_created_gt", "date_created_lt", "date_updated_gt", "date_updated_lt", "date_done_gt", "date_done_lt", "custom_fields", "custom_items"}},
	{name: "files.clickup.tasks.search", description: "Search tasks across a Workspace, 100 per page starting at page 0, filtered by Spaces, Folders (project_ids), Lists, statuses, assignees, tags, timestamps (ms) or custom_fields (JSON string)", method: http.MethodGet, path: "/api/v2/team/{team_id}/task", risk: domain.RiskRead, query: []string{"page", "order_by", "reverse", "subtasks", "space_ids", "project_ids", "list_ids", "statuses", "include_closed", "assignees", "tags", "due_date_gt", "due_date_lt", "date_created_gt", "date_created_lt", "date_updated_gt", "date_updated_lt", "date_done_gt", "date_done_lt", "custom_fields", "custom_items", "parent", "include_markdown_description"}},
	{name: "files.clickup.tasks.get", description: "Read one task with status, assignees, dates, custom fields, checklists and subtasks; pass custom_task_ids=true with team_id to use a custom task id", method: http.MethodGet, path: "/api/v2/task/{task_id}", risk: domain.RiskRead, query: []string{"custom_task_ids", "team_id", "include_subtasks", "include_markdown_description"}},
	{name: "files.clickup.tasks.create", description: "Create a task in a List", method: http.MethodPost, path: "/api/v2/list/{list_id}/task", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}, body: clickupTaskBody},
	{name: "files.clickup.tasks.update", description: "Update a task (fields not in the body stay unchanged)", method: http.MethodPut, path: "/api/v2/task/{task_id}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}, body: clickupTaskUpdateBody},
	{name: "files.clickup.tasks.delete", description: "Delete a task permanently", method: http.MethodDelete, path: "/api/v2/task/{task_id}", risk: domain.RiskDestructive, query: []string{"custom_task_ids", "team_id"}},
	{name: "files.clickup.task_templates.list", description: "List the task templates of a Workspace, paged from page 0", method: http.MethodGet, path: "/api/v2/team/{team_id}/taskTemplate", risk: domain.RiskRead, query: []string{"page"}},
	{name: "files.clickup.tasks.create_from_template", description: "Create a task in a List from a task template", method: http.MethodPost, path: "/api/v2/list/{list_id}/taskTemplate/{template_id}", risk: domain.RiskWrite, body: "name (required)"},
	{name: "files.clickup.task_members.list", description: "List the people who can access a task", method: http.MethodGet, path: "/api/v2/task/{task_id}/member", risk: domain.RiskRead},
	{name: "files.clickup.list_members.list", description: "List the people who can access a List", method: http.MethodGet, path: "/api/v2/list/{list_id}/member", risk: domain.RiskRead},
	{name: "files.clickup.view_tasks.list", description: "List the tasks shown by a view, 30 per page starting at page 0", method: http.MethodGet, path: "/api/v2/view/{view_id}/task", risk: domain.RiskRead, query: []string{"page"}},
	{name: "files.clickup.views.list", description: "List the views of a Workspace", method: http.MethodGet, path: "/api/v2/team/{team_id}/view", risk: domain.RiskRead},
	{name: "files.clickup.list_views.list", description: "List the views of a List", method: http.MethodGet, path: "/api/v2/list/{list_id}/view", risk: domain.RiskRead},
	// Comments.
	{name: "files.clickup.comments.list", description: "List the comments of a task, newest first, 25 per call; pass start (ms timestamp) and start_id of the oldest comment to continue", method: http.MethodGet, path: "/api/v2/task/{task_id}/comment", risk: domain.RiskRead, query: []string{"custom_task_ids", "team_id", "start", "start_id"}},
	{name: "files.clickup.comments.create", description: "Add a comment to a task", method: http.MethodPost, path: "/api/v2/task/{task_id}/comment", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}, body: clickupCommentBody},
	{name: "files.clickup.list_comments.list", description: "List the comments of a List", method: http.MethodGet, path: "/api/v2/list/{list_id}/comment", risk: domain.RiskRead, query: []string{"start", "start_id"}},
	{name: "files.clickup.list_comments.create", description: "Add a comment to a List", method: http.MethodPost, path: "/api/v2/list/{list_id}/comment", risk: domain.RiskWrite, body: clickupCommentBody},
	{name: "files.clickup.comment_replies.list", description: "List the threaded replies of a comment", method: http.MethodGet, path: "/api/v2/comment/{comment_id}/reply", risk: domain.RiskRead},
	{name: "files.clickup.comment_replies.create", description: "Reply to a comment", method: http.MethodPost, path: "/api/v2/comment/{comment_id}/reply", risk: domain.RiskWrite, body: clickupCommentBody},
	{name: "files.clickup.comments.update", description: "Edit, assign or resolve a comment", method: http.MethodPut, path: "/api/v2/comment/{comment_id}", risk: domain.RiskWrite, body: "comment_text, assignee (user id), resolved"},
	{name: "files.clickup.comments.delete", description: "Delete a comment", method: http.MethodDelete, path: "/api/v2/comment/{comment_id}", risk: domain.RiskDestructive},
	// Tags, custom fields, checklists, dependencies, links.
	{name: "files.clickup.tags.list", description: "List the tags of a Space", method: http.MethodGet, path: "/api/v2/space/{space_id}/tag", risk: domain.RiskRead},
	{name: "files.clickup.tags.create", description: "Create a tag in a Space", method: http.MethodPost, path: "/api/v2/space/{space_id}/tag", risk: domain.RiskWrite, body: "tag {name (required), tag_fg, tag_bg} with hex colours"},
	{name: "files.clickup.tags.add", description: "Add an existing Space tag to a task (tag_name without spaces)", method: http.MethodPost, path: "/api/v2/task/{task_id}/tag/{tag_name}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}},
	{name: "files.clickup.tags.remove", description: "Remove a tag from a task", method: http.MethodDelete, path: "/api/v2/task/{task_id}/tag/{tag_name}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}},
	{name: "files.clickup.custom_fields.list", description: "List the custom fields available on a List with their ids, types and options", method: http.MethodGet, path: "/api/v2/list/{list_id}/field", risk: domain.RiskRead},
	{name: "files.clickup.custom_fields.set", description: "Set the value of a custom field on a task", method: http.MethodPost, path: "/api/v2/task/{task_id}/field/{field_id}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}, body: "value (required, shaped by the field type) and optional value_options"},
	{name: "files.clickup.custom_fields.remove", description: "Clear a custom field value on a task", method: http.MethodDelete, path: "/api/v2/task/{task_id}/field/{field_id}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}},
	{name: "files.clickup.checklists.create", description: "Create a checklist on a task", method: http.MethodPost, path: "/api/v2/task/{task_id}/checklist", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}, body: "name (required)"},
	{name: "files.clickup.checklists.update", description: "Rename or reorder a checklist", method: http.MethodPut, path: "/api/v2/checklist/{checklist_id}", risk: domain.RiskWrite, body: "name, position"},
	{name: "files.clickup.checklists.delete", description: "Delete a checklist", method: http.MethodDelete, path: "/api/v2/checklist/{checklist_id}", risk: domain.RiskDestructive},
	{name: "files.clickup.checklist_items.create", description: "Add an item to a checklist", method: http.MethodPost, path: "/api/v2/checklist/{checklist_id}/checklist_item", risk: domain.RiskWrite, body: "name (required), assignee (user id)"},
	{name: "files.clickup.checklist_items.update", description: "Edit, assign, resolve or nest a checklist item", method: http.MethodPut, path: "/api/v2/checklist/{checklist_id}/checklist_item/{checklist_item_id}", risk: domain.RiskWrite, body: "name, assignee (user id), resolved, parent (checklist item id)"},
	{name: "files.clickup.checklist_items.delete", description: "Delete a checklist item", method: http.MethodDelete, path: "/api/v2/checklist/{checklist_id}/checklist_item/{checklist_item_id}", risk: domain.RiskDestructive},
	{name: "files.clickup.dependencies.add", description: "Make a task wait on another (depends_on) or block another (dependency_of)", method: http.MethodPost, path: "/api/v2/task/{task_id}/dependency", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}, body: "exactly one of depends_on or dependency_of (task id)"},
	{name: "files.clickup.dependencies.remove", description: "Remove a dependency; pass exactly one of depends_on or dependency_of", method: http.MethodDelete, path: "/api/v2/task/{task_id}/dependency", risk: domain.RiskWrite, query: []string{"depends_on", "dependency_of", "custom_task_ids", "team_id"}},
	{name: "files.clickup.links.add", description: "Link two tasks", method: http.MethodPost, path: "/api/v2/task/{task_id}/link/{links_to}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}},
	{name: "files.clickup.links.remove", description: "Remove the link between two tasks", method: http.MethodDelete, path: "/api/v2/task/{task_id}/link/{links_to}", risk: domain.RiskWrite, query: []string{"custom_task_ids", "team_id"}},
	// Lists, Folders, Spaces.
	{name: "files.clickup.lists.create", description: "Create a List inside a Folder", method: http.MethodPost, path: "/api/v2/folder/{folder_id}/list", risk: domain.RiskWrite, body: clickupListBody},
	{name: "files.clickup.lists.create_folderless", description: "Create a List directly in a Space", method: http.MethodPost, path: "/api/v2/space/{space_id}/list", risk: domain.RiskWrite, body: clickupListBody},
	{name: "files.clickup.lists.update", description: "Rename a List or change its description, due date, priority, assignee, status or unset_status", method: http.MethodPut, path: "/api/v2/list/{list_id}", risk: domain.RiskWrite, body: "name, content, due_date, due_date_time, priority, assignee, status, unset_status"},
	{name: "files.clickup.lists.delete", description: "Delete a List and every task in it", method: http.MethodDelete, path: "/api/v2/list/{list_id}", risk: domain.RiskDestructive},
	{name: "files.clickup.folders.create", description: "Create a Folder in a Space", method: http.MethodPost, path: "/api/v2/space/{space_id}/folder", risk: domain.RiskWrite, body: "name (required)"},
	{name: "files.clickup.folders.update", description: "Rename a Folder", method: http.MethodPut, path: "/api/v2/folder/{folder_id}", risk: domain.RiskWrite, body: "name (required)"},
	{name: "files.clickup.folders.delete", description: "Delete a Folder with its Lists and tasks", method: http.MethodDelete, path: "/api/v2/folder/{folder_id}", risk: domain.RiskDestructive},
	{name: "files.clickup.spaces.create", description: "Create a Space in a Workspace", method: http.MethodPost, path: "/api/v2/team/{team_id}/space", risk: domain.RiskWrite, body: "name (required), multiple_assignees, features {due_dates, time_tracking, tags, time_estimates, checklists, custom_fields, remap_dependencies, dependency_warning, portfolios}"},
	{name: "files.clickup.spaces.update", description: "Rename a Space or change its colour, privacy, admin_can_manage, archived flag or features", method: http.MethodPut, path: "/api/v2/space/{space_id}", risk: domain.RiskWrite, body: "name, color, private, admin_can_manage, multiple_assignees, features, archived"},
	{name: "files.clickup.spaces.delete", description: "Delete a Space with everything inside it", method: http.MethodDelete, path: "/api/v2/space/{space_id}", risk: domain.RiskDestructive},
	// Goals.
	{name: "files.clickup.goals.list", description: "List the Goals of a Workspace", method: http.MethodGet, path: "/api/v2/team/{team_id}/goal", risk: domain.RiskRead, query: []string{"include_completed"}},
	{name: "files.clickup.goals.get", description: "Read one Goal with its key results (targets)", method: http.MethodGet, path: "/api/v2/goal/{goal_id}", risk: domain.RiskRead},
	{name: "files.clickup.goals.create", description: "Create a Goal", method: http.MethodPost, path: "/api/v2/team/{team_id}/goal", risk: domain.RiskWrite, body: "name (required), due_date (ms), description, multiple_owners, owners (user ids), color"},
	{name: "files.clickup.goals.update", description: "Update a Goal", method: http.MethodPut, path: "/api/v2/goal/{goal_id}", risk: domain.RiskWrite, body: "name, due_date, description, rem_owners, add_owners, color"},
	{name: "files.clickup.goals.delete", description: "Delete a Goal", method: http.MethodDelete, path: "/api/v2/goal/{goal_id}", risk: domain.RiskDestructive},
	{name: "files.clickup.key_results.create", description: "Add a key result (target) to a Goal", method: http.MethodPost, path: "/api/v2/goal/{goal_id}/key_result", risk: domain.RiskWrite, body: "name (required), owners, type (number, currency, boolean, percentage or automatic), steps_start, steps_end, unit, task_ids, list_ids"},
	{name: "files.clickup.key_results.update", description: "Update a key result's progress or note", method: http.MethodPut, path: "/api/v2/key_result/{key_result_id}", risk: domain.RiskWrite, body: "steps_current, note"},
	{name: "files.clickup.key_results.delete", description: "Delete a key result", method: http.MethodDelete, path: "/api/v2/key_result/{key_result_id}", risk: domain.RiskDestructive},
	// Time tracking.
	{name: "files.clickup.time_entries.list", description: "List time entries of a Workspace for the last 30 days or a start_date/end_date range (ms), optionally for one assignee (user id) or one Space, Folder, List or task", method: http.MethodGet, path: "/api/v2/team/{team_id}/time_entries", risk: domain.RiskRead, query: []string{"start_date", "end_date", "assignee", "include_task_tags", "include_location_names", "space_id", "folder_id", "list_id", "task_id", "custom_task_ids", "include_approval_history", "include_approval_details"}},
	{name: "files.clickup.time_entries.get", description: "Read one time entry", method: http.MethodGet, path: "/api/v2/team/{team_id}/time_entries/{timer_id}", risk: domain.RiskRead},
	{name: "files.clickup.time_entries.current", description: "Read the timer currently running for the authorized user or the given assignee", method: http.MethodGet, path: "/api/v2/team/{team_id}/time_entries/current", risk: domain.RiskRead, query: []string{"assignee"}},
	{name: "files.clickup.time_entries.create", description: "Record a time entry", method: http.MethodPost, path: "/api/v2/team/{team_id}/time_entries", risk: domain.RiskWrite, query: []string{"custom_task_ids"}, body: "start (ms, required), duration (ms, required), description, tags, billable, assignee (user id), tid (task id)"},
	{name: "files.clickup.time_entries.update", description: "Update a time entry", method: http.MethodPut, path: "/api/v2/team/{team_id}/time_entries/{timer_id}", risk: domain.RiskWrite, query: []string{"custom_task_ids"}, body: "description, tags, tag_action, start, end, duration, billable, tid"},
	{name: "files.clickup.time_entries.delete", description: "Delete a time entry", method: http.MethodDelete, path: "/api/v2/team/{team_id}/time_entries/{timer_id}", risk: domain.RiskDestructive},
	{name: "files.clickup.time_entries.start", description: "Start a timer for the authorized user", method: http.MethodPost, path: "/api/v2/team/{team_id}/time_entries/start", risk: domain.RiskWrite, query: []string{"custom_task_ids"}, body: "tid (task id), description, tags, billable"},
	{name: "files.clickup.time_entries.stop", description: "Stop the running timer of the authorized user", method: http.MethodPost, path: "/api/v2/team/{team_id}/time_entries/stop", risk: domain.RiskWrite},
	// Docs and chat (API v3).
	{name: "files.clickup.docs.list", description: "Search the Docs of a Workspace; filter by id, creator, parent, archived or deleted and follow next_cursor for more", method: http.MethodGet, path: "/api/v3/workspaces/{workspace_id}/docs", risk: domain.RiskRead, query: []string{"id", "creator", "deleted", "archived", "parent_id", "parent_type", "limit", "next_cursor"}},
	{name: "files.clickup.docs.get", description: "Read the metadata of one Doc", method: http.MethodGet, path: "/api/v3/workspaces/{workspace_id}/docs/{doc_id}", risk: domain.RiskRead},
	{name: "files.clickup.doc_pages.list", description: "Read the pages of a Doc with their content (text/md by default)", method: http.MethodGet, path: "/api/v3/workspaces/{workspace_id}/docs/{doc_id}/pages", risk: domain.RiskRead, query: []string{"max_page_depth", "content_format"}},
	{name: "files.clickup.doc_pages.get", description: "Read one Doc page with its content", method: http.MethodGet, path: "/api/v3/workspaces/{workspace_id}/docs/{doc_id}/pages/{page_id}", risk: domain.RiskRead, query: []string{"content_format"}},
	{name: "files.clickup.docs.create", description: "Create a Doc", method: http.MethodPost, path: "/api/v3/workspaces/{workspace_id}/docs", risk: domain.RiskWrite, body: clickupDocBody},
	{name: "files.clickup.doc_pages.create", description: "Add a page to a Doc", method: http.MethodPost, path: "/api/v3/workspaces/{workspace_id}/docs/{doc_id}/pages", risk: domain.RiskWrite, body: clickupPageBody},
	{name: "files.clickup.doc_pages.update", description: "Edit a Doc page; content_edit_mode replace, append or prepend", method: http.MethodPut, path: "/api/v3/workspaces/{workspace_id}/docs/{doc_id}/pages/{page_id}", risk: domain.RiskWrite, body: "name, sub_title, content, content_edit_mode (replace, append, prepend), content_format"},
	{name: "files.clickup.chat_channels.list", description: "List the Chat channels of a Workspace; follow next_cursor for more", method: http.MethodGet, path: "/api/v3/workspaces/{workspace_id}/chat/channels", risk: domain.RiskRead, query: []string{"limit", "next_cursor", "is_follower", "include_hidden", "with_comment_since"}},
	{name: "files.clickup.chat_messages.list", description: "List the messages of a Chat channel; follow next_cursor for older messages", method: http.MethodGet, path: "/api/v3/workspaces/{workspace_id}/chat/channels/{channel_id}/messages", risk: domain.RiskRead, query: []string{"limit", "next_cursor", "content_format"}},
	{name: "files.clickup.chat_messages.create", description: "Post a message in a Chat channel", method: http.MethodPost, path: "/api/v3/workspaces/{workspace_id}/chat/channels/{channel_id}/messages", risk: domain.RiskPublish, body: "type (message), content (required), content_format (text/md or text/plain)"},
	{name: "files.clickup.webhooks.list", description: "List the webhooks registered by the authorized user in a Workspace", method: http.MethodGet, path: "/api/v2/team/{team_id}/webhook", risk: domain.RiskRead},
}

// Both the origin and every method/path are static manifest data. Identifiers
// never determine a host, API version or arbitrary path; the raw escape covers
// documented v2/v3 endpoints only and never the OAuth token exchange.
func clickupManifest() Manifest {
	operations := make([]OperationManifest, 0, len(clickupOperations)+1)
	for _, operation := range clickupOperations {
		operations = append(operations, operation.manifest())
	}
	operations = append(operations, OperationManifest{
		Name: "files.clickup.raw", Description: "Call a documented ClickUp REST endpoint under /api/v2/ or /api/v3/ on the fixed api.clickup.com origin",
		Risk: domain.RiskRaw, Body: BodyRaw, InputSchema: rawSchema(), IdempotencyHeader: "Idempotency-Key", Retry: readRetry,
		Raw: &RawPolicy{Methods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}, PathPrefixes: []string{"/api/v2/", "/api/v3/"}},
	})
	return Manifest{
		Provider: "clickup", Capability: domain.Files, APIVersion: clickupAPIVersion,
		OriginKind: OriginFixed, Origin: clickupOrigin,
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
		MaxRequestBytes: clickupMaxRequestBytes, MaxResponseBytes: defaultMaxResponseBytes, Operations: operations,
	}
}

func (operation clickupOperation) manifest() OperationManifest {
	parameters := clickupPathParameters(operation.path)
	required := append([]string(nil), parameters...)
	query := make(map[string]string, len(operation.query))
	for _, name := range operation.query {
		query[name] = clickupQueryKey(name)
	}
	manifest := OperationManifest{
		Name: operation.name, Description: operation.description, Risk: operation.risk,
		Method: operation.method, Path: operation.path, Query: query, Body: BodyNone, Retry: readRetry,
	}
	if operation.method != http.MethodGet {
		// ClickUp ignores idempotency keys, so a create or delete is sent once;
		// PUT updates are idempotent by construction and may retry.
		manifest.IdempotencyHeader = "Idempotency-Key"
		manifest.Retry = noRetry
		if operation.method == http.MethodPut {
			manifest.Retry = idempotentWriteRetry
		}
		if operation.body != "" {
			manifest.Body = BodyJSON
			required = append(required, "body")
		}
	}
	manifest.Required = required
	manifest.InputSchema = clickupSchema(parameters, operation.query, operation.body, required)
	return manifest
}

func clickupPathParameters(path string) []string {
	var parameters []string
	for _, match := range pathTemplatePattern.FindAllStringSubmatch(path, -1) {
		parameters = append(parameters, match[1])
	}
	return parameters
}

func clickupQueryKey(name string) string {
	if clickupListArgs[name] {
		return name + "[]"
	}
	return name
}

func clickupSchema(parameters, query []string, body string, required []string) json.RawMessage {
	properties := map[string]any{
		"connection_id": boundedStringProperty(128),
		"provider":      map[string]any{"type": "string", "const": "clickup"},
	}
	for _, name := range parameters {
		properties[name] = clickupArguments[name].schema
	}
	for _, name := range query {
		properties[name] = clickupArguments[name].schema
	}
	if body != "" {
		properties["body"] = map[string]any{"type": "object", "description": body, "additionalProperties": true}
	}
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	encoded, _ := json.Marshal(schema)
	return encoded
}

type clickupArgument struct {
	schema map[string]any
	valid  func(json.RawMessage) bool
}

// clickupIDValue accepts an identifier as a JSON string or, because most
// ClickUp ids are numeric and models send them as numbers, as a JSON integer.
func clickupIDValue(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	if trimmed[0] != '"' {
		// Only a plain non-negative integer literal is an identifier; floats,
		// exponents, booleans, objects and arrays are not.
		if !clickupNumericID.Match(trimmed) {
			return "", false
		}
		return string(trimmed), true
	}
	value := jsonString(raw)
	if value == "" || !clickupIDPattern.MatchString(value) {
		return "", false
	}
	return value, true
}

func clickupID(description string) clickupArgument {
	return clickupArgument{
		schema: map[string]any{"type": []string{"string", "integer"}, "pattern": clickupIDPattern.String(), "description": description},
		valid:  func(raw json.RawMessage) bool { _, ok := clickupIDValue(raw); return ok },
	}
}

func clickupIDList(description string, maximum int) clickupArgument {
	return clickupArgument{
		schema: map[string]any{"type": "array", "items": map[string]any{"type": []string{"string", "integer"}, "pattern": clickupIDPattern.String()}, "maxItems": maximum, "description": description},
		valid: func(raw json.RawMessage) bool {
			var items []json.RawMessage
			if len(raw) == 0 || json.Unmarshal(raw, &items) != nil || len(items) > maximum {
				return false
			}
			for _, item := range items {
				if _, ok := clickupIDValue(item); !ok {
					return false
				}
			}
			return true
		},
	}
}

func clickupTextList(description string, maximum int) clickupArgument {
	return clickupArgument{
		schema: map[string]any{"type": "array", "items": map[string]any{"type": "string", "maxLength": 128}, "maxItems": maximum, "description": description},
		valid: func(raw json.RawMessage) bool {
			return len(raw) > 0 && optionalStringList(raw, maximum, clickupTextValue.MatchString)
		},
	}
}

func clickupIntegerList(description string, minimum, maximum, count int) clickupArgument {
	return clickupArgument{
		schema: map[string]any{"type": "array", "items": integerProperty(minimum, maximum), "maxItems": count, "description": description},
		valid: func(raw json.RawMessage) bool {
			var values []int
			if len(raw) == 0 || json.Unmarshal(raw, &values) != nil || len(values) > count {
				return false
			}
			for _, value := range values {
				if value < minimum || value > maximum {
					return false
				}
			}
			return true
		},
	}
}

func clickupBoolean(description string) clickupArgument {
	return clickupArgument{
		schema: map[string]any{"type": "boolean", "description": description},
		valid:  func(raw json.RawMessage) bool { return len(raw) > 0 && optionalBoolean(raw) },
	}
}

func clickupInteger(description string, minimum, maximum int) clickupArgument {
	schema := integerProperty(minimum, maximum)
	schema["description"] = description
	return clickupArgument{
		schema: schema,
		valid:  func(raw json.RawMessage) bool { return len(raw) > 0 && optionalInteger(raw, minimum, maximum) },
	}
}

func clickupTimestamp(description string) clickupArgument {
	// Milliseconds since the Unix epoch up to the year 2100.
	return clickupInteger(description+" (ms since the Unix epoch)", 0, 4102444800000)
}

func clickupEnum(description string, values ...string) clickupArgument {
	allowed := make(map[string]bool, len(values))
	for _, value := range values {
		allowed[value] = true
	}
	return clickupArgument{
		schema: map[string]any{"type": "string", "enum": values, "description": description},
		valid:  func(raw json.RawMessage) bool { return allowed[jsonString(raw)] },
	}
}

func clickupString(description string, maximum int) clickupArgument {
	schema := boundedStringProperty(maximum)
	schema["description"] = description
	return clickupArgument{
		schema: schema,
		valid: func(raw json.RawMessage) bool {
			return len(raw) > 0 && optionalBoundedString(raw, maximum)
		},
	}
}

// clickupCustomFieldFilter accepts ClickUp's custom_fields query filter either
// as the JSON-encoded string the API expects or as a JSON array, which the
// validator serializes for the query string.
func clickupCustomFieldFilter() clickupArgument {
	return clickupArgument{
		schema: map[string]any{"type": []string{"string", "array"}, "maxLength": 8192, "description": "Custom field filters, for example [{\"field_id\":\"…\",\"operator\":\"=\",\"value\":\"…\"}], as a JSON string or array"},
		valid: func(raw json.RawMessage) bool {
			if len(raw) == 0 || len(raw) > 8192 {
				return false
			}
			trimmed := bytes.TrimSpace(raw)
			if len(trimmed) > 0 && trimmed[0] == '[' {
				return json.Valid(trimmed)
			}
			value := jsonString(raw)
			return value != "" && json.Valid([]byte(value))
		},
	}
}

var clickupArguments = map[string]clickupArgument{
	"team_id":                      clickupID("ClickUp Workspace (team) id from workspaces.list"),
	"workspace_id":                 clickupID("ClickUp Workspace (team) id from workspaces.list"),
	"space_id":                     clickupID("Space id"),
	"folder_id":                    clickupID("Folder id"),
	"list_id":                      clickupID("List id"),
	"task_id":                      clickupID("Task id, or a custom task id together with custom_task_ids=true and team_id"),
	"comment_id":                   clickupID("Comment id"),
	"goal_id":                      clickupID("Goal id"),
	"key_result_id":                clickupID("Key result (target) id"),
	"checklist_id":                 clickupID("Checklist id"),
	"checklist_item_id":            clickupID("Checklist item id"),
	"field_id":                     clickupID("Custom field id from custom_fields.list"),
	"timer_id":                     clickupID("Time entry id"),
	"view_id":                      clickupID("View id"),
	"template_id":                  clickupID("Task template id from task_templates.list"),
	"doc_id":                       clickupID("Doc id"),
	"page_id":                      clickupID("Doc page id"),
	"channel_id":                   clickupID("Chat channel id"),
	"links_to":                     clickupID("Id of the task to link"),
	"tag_name":                     clickupID("Tag name without spaces"),
	"start_id":                     clickupID("Comment id to continue from"),
	"parent":                       clickupID("Parent task id"),
	"parent_id":                    clickupID("Parent id (Space, Folder, List or Workspace)"),
	"assignee":                     clickupID("User id"),
	"creator":                      clickupID("Creator user id"),
	"id":                           clickupID("Doc id to filter by"),
	"depends_on":                   clickupID("Task id this task waits on"),
	"dependency_of":                clickupID("Task id that waits on this task"),
	"group_ids":                    clickupString("Comma-separated user group ids", 1024),
	"space_ids":                    clickupIDList("Space ids", 100),
	"project_ids":                  clickupIDList("Folder ids", 100),
	"list_ids":                     clickupIDList("List ids", 100),
	"assignees":                    clickupIDList("User ids", 100),
	"watchers":                     clickupIDList("User ids", 100),
	"statuses":                     clickupTextList("Status names exactly as configured", 50),
	"tags":                         clickupTextList("Tag names", 50),
	"custom_items":                 clickupIntegerList("Custom task type ids (0 for task, 1 for milestone)", 0, 1000000000, 50),
	"archived":                     clickupBoolean("Include archived items"),
	"reverse":                      clickupBoolean("Reverse the sort order"),
	"subtasks":                     clickupBoolean("Include subtasks"),
	"include_closed":               clickupBoolean("Include closed tasks"),
	"include_markdown_description": clickupBoolean("Return descriptions as markdown"),
	"include_subtasks":             clickupBoolean("Include subtasks"),
	"custom_task_ids":              clickupBoolean("Treat task_id as a custom task id (requires team_id)"),
	"include_completed":            clickupBoolean("Include completed goals"),
	"include_task_tags":            clickupBoolean("Include task tags"),
	"include_location_names":       clickupBoolean("Include Space, Folder and List names"),
	"include_approval_history":     clickupBoolean("Include approval history"),
	"include_approval_details":     clickupBoolean("Include approval details"),
	"deleted":                      clickupBoolean("Include deleted Docs"),
	"is_follower":                  clickupBoolean("Only channels the user follows"),
	"include_hidden":               clickupBoolean("Include hidden channels"),
	"page":                         clickupInteger("Zero-based page number", 0, 100000),
	"limit":                        clickupInteger("Maximum items to return", 1, 1000),
	"max_page_depth":               clickupInteger("Maximum page depth, -1 for all", -1, 100),
	"start":                        clickupTimestamp("Timestamp of the comment to continue from"),
	"start_date":                   clickupTimestamp("Range start"),
	"end_date":                     clickupTimestamp("Range end"),
	"due_date_gt":                  clickupTimestamp("Due after"),
	"due_date_lt":                  clickupTimestamp("Due before"),
	"date_created_gt":              clickupTimestamp("Created after"),
	"date_created_lt":              clickupTimestamp("Created before"),
	"date_updated_gt":              clickupTimestamp("Updated after"),
	"date_updated_lt":              clickupTimestamp("Updated before"),
	"date_done_gt":                 clickupTimestamp("Completed after"),
	"date_done_lt":                 clickupTimestamp("Completed before"),
	"with_comment_since":           clickupTimestamp("Only channels with comments since"),
	"order_by":                     clickupEnum("Sort field", "id", "created", "updated", "due_date"),
	"content_format":               clickupEnum("Content format", "text/md", "text/plain", "text/html"),
	"parent_type":                  clickupEnum("Parent type", "SPACE", "FOLDER", "LIST", "EVERYTHING", "WORKSPACE"),
	"custom_fields":                clickupCustomFieldFilter(),
	"next_cursor":                  clickupString("Cursor from the previous page", 4096),
}

// validateClickUpArguments runs before approval and before credential
// resolution. Every argument must be a declared path slot, query key or the
// JSON body of its operation, so nothing can reach headers, the origin or a
// different endpoint.
func validateClickUpArguments(operation OperationManifest, arguments map[string]json.RawMessage) error {
	if operation.Raw != nil {
		path := jsonString(arguments["path"])
		if strings.HasPrefix(path, "/api/v2/oauth/") || strings.HasPrefix(path, "/api/v3/oauth/") {
			return domain.ErrInvalidArguments
		}
		return nil
	}
	allowed := map[string]bool{"connection_id": true, "provider": true, "expected_external_id": true}
	for _, name := range clickupPathParameters(operation.Path) {
		allowed[name] = true
	}
	for name := range operation.Query {
		allowed[name] = true
	}
	if operation.Body == BodyJSON {
		allowed["body"] = true
	}
	for name, raw := range arguments {
		if !allowed[name] {
			return domain.ErrInvalidArguments
		}
		switch name {
		case "provider":
			if jsonString(raw) != "clickup" {
				return domain.ErrInvalidArguments
			}
		case "connection_id":
			if !domain.ValidResourceID(jsonString(raw)) {
				return domain.ErrInvalidArguments
			}
		case "expected_external_id":
			if !optionalBoundedString(raw, 1024) {
				return domain.ErrInvalidArguments
			}
		case "body":
			if !isJSONObject(raw) {
				return domain.ErrInvalidArguments
			}
		default:
			rule, known := clickupArguments[name]
			if !known || !rule.valid(raw) {
				return domain.ErrInvalidArguments
			}
		}
	}
	if raw, exists := arguments["custom_fields"]; exists {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			compact, err := compactJSON(trimmed)
			if err != nil {
				return domain.ErrInvalidArguments
			}
			encoded, _ := json.Marshal(string(compact))
			arguments["custom_fields"] = encoded
		}
	}
	switch operation.Name {
	case "files.clickup.task_templates.list":
		// ClickUp requires the page number on this endpoint; default to the
		// first page instead of forwarding an invalid request.
		if _, exists := arguments["page"]; !exists {
			arguments["page"] = json.RawMessage("0")
		}
	case "files.clickup.dependencies.remove":
		_, dependsOn := arguments["depends_on"]
		_, dependencyOf := arguments["dependency_of"]
		if dependsOn == dependencyOf {
			return domain.ErrInvalidArguments
		}
	}
	return nil
}
