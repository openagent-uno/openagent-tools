# Calendar and mail prerelease 0.1.7

Status: [SDK 0.1.7 published](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.7) from `f2cecfe3672e48a7724324fef5e41072cde697bf`.
Go race/vet/govulncheck, twelve binaries, the Python wheel, public installed-host
acquisition and Linux-native runner/broker fixtures passed. The other five
targets have cross-build evidence only. [Qualification receipt](connector-calendar-mail-0.1.7-qualification.json).
Real Google/Microsoft OAuth acceptance remains pending; common enrollment for
these three providers is closed. Server 43/App 20 remain on SDK 0.1.6 and do not
include these entries. No provider is centrally enabled by adding a catalog descriptor.

| Connector | Provider | Typed operations | Initial boundary |
| --- | --- | --- | --- |
| Google Calendar | `google_calendar` | 7 | CalendarList and event pages/reads; event creation, PATCH and deletion |
| Outlook Mail | `outlook_mail` | 9 | Top-level mail folders, messages and attachments; text drafts and separately authorized send |
| Outlook Calendar | `outlook_calendar` | 7 | Calendars and event pages/reads; finite UTC event create/update/delete |

Each connected account is a separate local connection. The invoking host binds
workspace, connection and permissions; tool arguments cannot select credentials,
API origin, principal, arbitrary headers or raw provider methods. Microsoft OAuth
must verify `/me` using `User.Read` and bind that ID to the connection; it does not
parse an unverified identity JWT. Google Calendar uses the existing Google
confidential OAuth model without requesting unrelated identity scopes.

Google's default consent uses `calendar.calendarlist.readonly` and
`calendar.events`. The adapter also recognizes the documented broader and
read-only alternatives per method. Outlook reads recognize the method-specific
Microsoft scope hierarchy. `Mail.ReadWrite` never grants `Mail.Send`.
Local write permission is required independently of provider scopes.

Google hosts own query profiles, opaque page cursors and final `nextSyncToken`.
They must persist a projection and its checkpoint atomically; HTTP 410 requests
an explicit reset decision. Cancellation tombstones remain visible. Mutations
use exact strong ETags; HTTP 412 is returned without overwrite or retry.
Recurrence fields are bounded; recurring writes require paired times and IANA
zones. No attendees or conferencing parameters are accepted, although edits to
existing meetings may notify their existing guests.

Outlook cursor envelopes are bound to connection, verified account, operation
and fixed resource path. Provider next-links must retain the compiled Graph
origin/path/query allowlist. This subset does not provide delta synchronization,
recurrence expansion, attendee invitations, arbitrary OData, file upload or MIME.
Outlook Calendar writes accept UTC times. Version headers are forwarded, but
actual provider conditional-write behavior still requires real qualification.
Sending returns HTTP 202 acceptance, not a delivery guarantee.
Microsoft exposes no configured token-revocation endpoint here: local
disconnection must not be described as global Microsoft consent revocation.

All calls use fixed HTTPS origins, bounded JSON and a single HTTP attempt.
Successful 202/204 acknowledgements must have an empty body. Calendar and mail
widgets, synchronization engines, projections and editors are host compositions;
this work adds reusable connector operations rather than implementing those apps.

Before common enrollment: register or extend the existing provider apps,
preserve issuer metadata, test fresh
account consent plus refresh/restart/disconnection, and verify official logos in
the shared marketplace grid. Missing provider consent or approval keeps common
enrollment closed. Never report fixture tests as real OAuth acceptance.
