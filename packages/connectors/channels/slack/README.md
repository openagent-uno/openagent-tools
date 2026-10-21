# Managed Slack channel

`openagent-slack-channel/v1` connects one selected Slack channel to one explicitly
selected agent on an already registered host. This package is the central bot
custodian and bounded Slack API relay. The host uses its existing agent runtime,
identity, memory and tool grants through `openagent-channel-bridges`; it does not
receive a Slack bot access or refresh token.

This is an opt-in source implementation. Deployment, app configuration, consent
and real channel acceptance require their own evidence. Existing Slack import
connector qualification does not qualify this conversational channel.

## Existing official app and additive configuration

Use the existing OpenAgent Slack app `A0C9XC9JHTK`. Users connect that shared app;
they do not create a new app, supply `xoxb`/`xapp` credentials or configure Socket
Mode. This flow is separate from the existing `slack_import` user OAuth/MCP
connector, whose scopes, callback, grants and stored credentials are preserved.

The managed bot requests exactly these six **bot** scopes:

- `app_mentions:read`
- `channels:history`
- `channels:read`
- `chat:write`
- `groups:history`
- `groups:read`

It sends no `user_scope`. Missing or additional returned bot scopes are rejected;
rejection does not revoke or alter another grant. Workspace bot token rotation
must already be enabled. Non-expiring bot tokens, user credentials and enterprise
or organization-wide installations are outside this profile.

[app-manifest.additions.json](app-manifest.additions.json) is an **additive review
fragment**, not a replacement app manifest and not an executable setup command.
Export/read the current app configuration first. Merge the bot scope and event
arrays without deleting existing entries, append the new callback, and preserve
all existing user scopes, redirect URLs, client credentials and unrelated app
settings. Do not import this fragment over the existing manifest. If that app has
additional bot scopes, this exact six-scope profile needs an explicit compatibility
decision; do not remove permissions or revoke existing installations to make the
check pass.

For the public service origin `https://auth.openagent.uno`, the new routes are:

| Purpose | URL |
| --- | --- |
| Bot OAuth callback | `https://auth.openagent.uno/v1/channels/slack/oauth/callback` |
| Signed Events API and URL verification | `https://auth.openagent.uno/v1/channels/slack/events` |
| Existing user connector callback, preserved | `https://auth.openagent.uno/v1/oauth/slack_import/callback` |

Subscribe the bot to `app_mention`, `app_uninstalled` and `tokens_revoked`.
The HTTP ingress verifies the Slack signing-secret HMAC over the original body,
bounds its timestamp, and binds the app/workspace/event identifiers. This profile
requires the HTTP Events API route; it does not silently switch an app out of
Socket Mode or enable events in Slack. The template and source do not establish
that any console setting or grant has been applied.

Slack's [manifest reference](https://docs.slack.dev/reference/app-manifest/),
[OAuth guide](https://docs.slack.dev/authentication/installing-with-oauth/) and
[token rotation guide](https://docs.slack.dev/authentication/using-token-rotation/)
define the vendor fields. Bot `auth.test` identity is checked independently of
OAuth response metadata before accepting exchange or refresh credentials.

## Service configuration and custody

The auth executable mounts this optional service only when given
`--slack-channel-config=/absolute/path/slack-channel.json`. Existing OAuth/MCP
configuration remains separate. The configuration object is:

```json
{
  "origin": "https://auth.openagent.uno",
  "app_id": "A0C9XC9JHTK",
  "client_id": "<existing official app client ID>",
  "client_secret_file": "/secrets/slack-client-secret",
  "signing_secret_file": "/secrets/slack-signing-secret",
  "vault_path": "/state/slack-channel-v1.vault",
  "vault_key_id": "<active channel vault key ID>",
  "vault_key_files": {
    "<active channel vault key ID>": "/channel-keys/primary.hex"
  },
  "allowed_installations": ["<existing registered 64-character installation ID>"]
}
```

Angle-bracket values are placeholders requiring real operator configuration.
Secret files are protected absolute paths. Channel vault keys are 32 bytes in
hex. The encrypted channel vault must be a dedicated file, distinct from both
auth metadata and the MCP credential vault; startup compares the configured
paths and refuses connector records in a channel store. Retain the previous
vault keys while existing ciphertext still needs them. No automatic key
retirement or migration is implied.

One serialized app/workspace bot grant owns rotation centrally. No bot credential
is serialized into a public binding, session or host response. An interrupted
refresh requires explicit reconsent; an interrupted provider write remains
`outcome_unknown` and is not retried automatically. Disabling one binding does
not revoke the shared workspace bot and does not disconnect other destinations.
Workspace app uninstall or matching bot-token revocation fences its destinations.

## Host setup API

The Go `Client` uses an **existing** registered `auth.Identity`. It signs the exact
request body through the broker's normal nonce/rate/installation checks; this
channel client does not register or enroll a host. `Recipient` is the host's
explicit `(workspace_id, subject_id, agent_id)`, not a gateway session hint.

| Go method | HTTP route | Result |
| --- | --- | --- |
| `Start(ctx, StartRequest)` | `POST /v1/channels/slack/bindings` | Pending binding and browser consent URL |
| `Status(ctx, bindingID)` | `GET /v1/channels/slack/bindings/{id}` | Current binding metadata |
| `Activate(ctx, bindingID)` | `POST /v1/channels/slack/bindings/{id}/activate`, `{}` | Active binding after current channel checks |
| `Session(ctx, bindingID)` | `POST /v1/channels/slack/bindings/{id}/session`, `{}` | Private binding-scoped service session |
| `Disconnect(ctx, bindingID)` | `DELETE /v1/channels/slack/bindings/{id}` | Disconnected binding and invalidated session |

Example `StartRequest` body, with illustrative identifiers:

```json
{
  "recipient": {
    "workspace_id": "host-workspace",
    "subject_id": "host-subject",
    "agent_id": "selected-agent"
  },
  "agent_label": "Selected agent",
  "team_id": "TEXAMPLE",
  "channel_id": "CEXAMPLE"
}
```

The host verifies the recipient through its own authenticated product UI before
`Start`. The browser page names the host, recipient, agent, Slack workspace and
channel before continuing to Slack. Its one-time transaction expires after
15 minutes. After OAuth, `Status` becomes `authorized`; consent alone does not
activate the agent. Invite the bot to the selected channel and call `Activate`.
Activation requires current bot membership, the consenting Slack user's
membership, an unarchived non-DM channel, and a complete bounded member scan.
An incomplete proof fails closed. A Slack channel cannot have two live bindings
in this service, and no binding broadcasts to every host or every agent.

An issued service session lasts **8 hours**. Creating a new session replaces the
old session credential for that binding. This is a binding-scoped bearer
capability, not a Slack token. Keep it in private memory/pipe or the host's secret
store; do not place it in argv, command history, logs, settings exports or model
context. Renewal uses the already registered host's signed `Session` call.
Revocation or expiry stops intake; the child does not silently enroll or fall
back to operator-owned tokens.

## Hosted channel IPC

The `openagent-channel-bridges` source includes `HostedSlackBridge` and selects
it when Slack IPC configuration contains `service_origin`. Confirm that the
installed component actually contains this hosted mode before launch; older
Socket Mode-only releases do not acquire it through configuration.

Send this `channel-bridge-ipc/v1` frame through the child's private stdin. The
service binding ID and outer `binding_id` must be identical:

```json
{
  "protocol": "channel-bridge-ipc/v1",
  "type": "configure",
  "request_id": "configure-slack",
  "provider": "slack",
  "binding_id": "<service binding ID>",
  "config": {
    "service_origin": "https://auth.openagent.uno",
    "service_binding_id": "<same service binding ID>",
    "service_app_id": "A0C9XC9JHTK",
    "session_token": "<private service session token>",
    "context_messages": 20,
    "live": false
  }
}
```

These are placeholders, not credentials. No `bot_token` or `app_token` belongs in
hosted configuration. With `listen_channels` omitted the adapter selects only
the channel returned by this binding. Optional `allowed_users` adds a local
restriction; neither it nor `listen_channels` can broaden the server binding.
The host still supplies the normal IPC `start`, `authorize_context`,
`authorize_delivery`, `send`, `command` and lifecycle responses as applicable.
The service does not choose or start a second agent/runtime for the recipient.

The child serially polls `/bindings/{id}/inbox` using its service bearer, receives
at most ten bound deliveries, and uses `/api` only with that delivery ID. It
ACKs `/ack` with the exact delivery ID/body SHA-256 and `accepted` or `denied`.
ACK is transport custody state, not proof of a durable agent run by itself.

## Runtime, audience and replay requirements

The host must map the immutable binding and real Slack actor to its own principal,
agent, conversation and grants. `authorize_context` rechecks input admission;
`authorize_delivery` checks every freshly attested channel audience member before
model dispatch and each output chunk. Channel membership reads are bounded to
ten pages of 100; incomplete audiences do not authorize delivery. The host must
not treat the binding owner's identity, quoted history or a caller-selected
session ID as the current actor's authority.

Use a durable host run key including binding, provider account and event ID,
with the immutable accepted request/body hash. Replayed events and a restarted
child must find the same admitted run/outcome, not rerun tools or append another
message. Persist admission/outcome before acknowledging successful processing.
The bridge's process-local outcome cache is not a replacement for host runtime
idempotency. Writes use a service operation ID and durable `running`/`completed`
state; unknown outcomes require reconciliation, not a new ID and blind resend.

Provider operations are limited to `auth.test`, `conversations.info`,
`conversations.members`, `conversations.history`, `conversations.replies` and
`chat.postMessage`, always at fixed Slack API endpoints. The relay enforces the
bound channel and trigger/thread, excludes the trigger from history reads, and
disables message unfurls. Slack/host revocation is checked again around API
admission and response publication. Bot credentials never cross this boundary.

## Current limits and acceptance

- Text mentions and text replies only. Files/media, direct/group DMs, interactive
  pickers, slash-command ingress and a separate Slack MCP interface are not part
  of this managed profile. Unsupported media fails closed rather than being
  downloaded through an alternate credential or passed to another runtime.
- `context_messages` defaults to 20, accepts 0–100, and has a 65,536-byte UTF-8
  attributed-history bound. History remains quoted untrusted data. Thread scans
  that cannot reach their bounded end omit history rather than claim an old
  prefix is the latest context.
- The bot may hold workspace-level scopes; selected-channel routing and host ACLs
  constrain this service's use, not the vendor token's underlying permissions.
  The exact scope set is enforced even on cumulative Slack OAuth responses.
- Global routing, automatic enablement, cross-agent fallback and implicit host
  registration are absent. An installation allowlist or healthy endpoint does
  not prove channel consent, host ACLs, durable run recovery or actual replies.

Real acceptance must cover the chosen agent only, a denied actor/audience, a
second independent agent/host boundary, scoped history/replies, refresh and
restart without duplicate runs, session/host/channel revocation, uninstall and
replay. Preserve safe receipts without bot/session credentials or message bodies.
