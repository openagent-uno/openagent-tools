# Google data-access review correction — 23 October 2026

Google requested additional scope justification, exact agreement between code,
Console and consent, a replacement functional demonstration, and reproducible
reviewer access. This is an action-required review, not approval.

## Gmail least privilege

The implemented Gmail operations read messages/threads/attachments, create
drafts, and send. They do not modify existing mailbox messages or labels.
New grants therefore request `gmail.readonly` for read operations and
`gmail.compose` for draft/send operations. The former `gmail.modify` and
redundant `gmail.send` defaults were removed. Selecting read operations alone
does not request draft/send access. Google Console's declared union and its
three justification fields were updated on 23 October.

Existing host-held grants retain their original registration and scope set.
The compatibility exception applies to refresh and supported operation checks,
never new consent or code exchange. Returned scope expansion remains rejected.
Changing authorization requirements changes the signed Gmail contract: central
handles pinned to an earlier contract require explicit reconnection, rather
than silent migration. A service deployment must advance the catalog revision.

## Scope-to-function mapping

| Connector | Requested scopes | Actual central operations | Narrower alternative |
| --- | --- | --- | --- |
| Gmail | `gmail.readonly`, `gmail.compose` | Message list/get, thread get, attachment get, draft create/send, message send | Metadata omits content; readonly cannot create drafts/send; compose does not read the mailbox; send alone cannot manage drafts. |
| Drive | `drive` | Search, metadata get, content download/create/update | Readonly cannot write; `drive.file` excludes arbitrary existing files that were not created/opened/shared with this app. |
| Calendar | `calendar.calendarlist.readonly`, `calendar.events` | Calendar list/get and event list/get/create/update/delete | Event readonly cannot write; owned-only excludes calendars shared with the user; app-created excludes existing calendars. |
| Analytics | `analytics.readonly` | Account/property summaries, metadata, historical reports, realtime reports | These are read operations; no Analytics administration writes are requested. |

The Console union describes the app's separate connector flows. Each flow
requests only its connector's scopes, not the union across Google services.
Host tool admission remains additional to the provider's OAuth permissions.
Do not describe it as narrowing the provider token itself.

## Accurate processing disclosure

The October 19 submission described the legacy local-execution profile.
The optional central/v1 profile keeps encrypted provider credentials in the
service vault, performs selected provider calls there and returns opaque handles
and authorized results. The legacy runner instead keeps credentials and normal
API calls with the receiving host. The current
[privacy notice](https://openagent.uno/privacy) describes both. A new submission
must identify the profile actually demonstrated and must not imply local-only
custody for central execution.

## Remaining review evidence

The previous video is historical evidence, not proof of the revised scopes.
Its replacement must show expanded readable consent for each connector, the
actual user operations, and corresponding changes in Gmail, Drive and Calendar.
Drive's broad-access case needs an existing file created outside OpenAgent;
Analytics reporting needs an accessible GA4 property. Show only neutral QA
content. Do not claim mailbox modification, Drive deletion, raw operations,
or permanent deletion as part of the finite central catalog.

Provide tested instructions for the actual application/SDK path and any
required review enrollment. Do not distribute an owner's installation key,
Google credentials or reusable tokens. A prepared response or uploaded video
does not establish acceptance, and technical qualification does not replace
restricted-scope verification or an applicable security assessment.

References: [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes),
[Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[Calendar scopes](https://developers.google.com/workspace/calendar/api/auth),
[restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification).
