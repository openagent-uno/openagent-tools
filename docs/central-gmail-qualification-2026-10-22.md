# Gmail central qualification — 22 October 2026

**The seven-operation central Gmail surface has passed technical qualification
with composite evidence. General availability remains disabled while Google's
data-access review is pending.** The internal attachment defect is fixed; the
remaining provider review is a separate release condition.

The [sanitized receipt](../deploy/connector-auth/qualification-2026-10-22-central-gmail.json)
records the source versions, operation comparisons, test results and boundaries.
It contains no account, connection, message or attachment identifiers, consent
links, credentials or fixture contents.

## What was exercised

| Live source | Operations and observations |
| --- | --- |
| `3432f2587ce607474af1586851764aad2d05213a` | `drafts.create`, `drafts.send`, `messages.send`, `messages.get`, `messages.list` and `threads.get`; two new synthetic self-addressed messages, bounded pagination and no unrelated mail. Attachment read exposed the identifier defect. |
| `20487d4ca1e2701a1f0bb1008dbd6bafcb4e5bd3` | `messages.get` reread those exact two messages; `attachments.get` retrieved their existing attachment using its actual 404-character identifier. The download was exactly 100,352 bytes (98 KiB) and matched the original SHA-256. No additional message was created or sent. |

The six other operation contracts, schema functions and argument-validation
branches are unchanged. The complete central, authentication and OAuth source
trees are also unchanged by the attachment correction. This supports carrying
their observed evidence forward; it does **not** mean all seven operations were
reexecuted under the new grant.

The original central lifecycle included fresh consent and encrypted save,
explicit refresh, actual service/vault restart and same-message reread,
metadata-only invocation replay, rejection of a changed request at the same
invocation ID, wrong-recipient rejection, owned disconnect and subsequent denial.
The corrected service used a clean build of `20487d4`, with `vcs.modified=false`.

The regression fails against the original source and passes after the fix.
Across providers, central service and authentication, **338 top-level tests and
862 subtests passed**, including four new identifier regressions. Validation and
the service-only Linux build ran sequentially under the shared resource monitor.
No new SDK or client build was required.

## Identifier and transport limits

Gmail returned a valid attachment identifier longer than the old 256-character
limit. Attachment IDs now have their own ASCII URL-safe validation and a local
maximum of 4096 bytes. Message, thread, draft and label IDs retain their existing
256 limit. The generic HTTP path parameter limit remains 512; only the fixed
Gmail attachment operation uses the bounded attachment validator for that
parameter. Google's [attachment API reference](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages.attachments/get)
defines the identifier as a string; 4096 is an OpenAgent guard, not a claimed
Google maximum.

The central transport independently permits at most **256 KiB of encoded
operation arguments** and a **1 MiB complete HTTP request**. MIME/base64 encoding
means a raw 1 MiB attachment does not fit these limits. The verified 98 KiB
example is not a claim about the maximum supported attachment size.

## Versioning, custody and cleanup

Changing the attachment schema changes the Gmail contract. The signed public
catalog advanced from revision 2 to 3 and the private admission from revision 1
to 2, preserving its original audience and expiry. The other 114 descriptors
remained identical. The old private grant failed closed and remained removable
by its owner. No implicit credential or contract migration was introduced.

This qualification uses the opt-in central execution architecture: the service
holds credentials in its encrypted vault and performs provider requests;
consumers receive handles and authorized results, not reusable provider tokens.
Invocation replay stores admission/outcome metadata rather than mail contents.
The public [privacy disclosure](https://openagent.uno/privacy) describes central
custody and processing. Google review evidence must describe that same path.

Both generated messages were moved to recoverable Trash through the existing
owner Gmail connector after exact metadata checks; ordinary central reads then
verified their Trash labels. This does not add a central Trash tool. QA handles
were disconnected. No permanent deletion, unrelated-mail change or global
provider revocation was performed. The temporary private admission remains
configured; its removal was not part of this documentation publication.

## Availability and remaining boundaries

An authenticated Google Cloud observation on 22 October confirmed the AI-agent
client setting enabled, branding and home page complete, and data access still
in review. Privacy, app functionality, appropriate access, minimum scopes and
additional requirements remained under review. No restricted-scope approval or
completed security assessment is claimed. Successful private OAuth and API calls
do not establish general approval; Google's [unverified-app requirements](https://support.google.com/cloud/answer/7454865?hl=en)
and [restricted-scope requirements](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification)
remain separate from the internal code qualification.

Gmail is still unavailable in the public central catalog. After provider gates
and operator approval, normal activation can retain the same image, app, scopes,
keys and vault, remove the private admission and add `gmail` to
`qualified_catalog_ids`. Availability changes require public revision 4 or later.
Clients use the ordinary signed catalog, `Create` without `qualification_id`,
hosted consent, status/`Complete`, local host authorization and permitted
handle-based invocation. No consumer-specific OAuth implementation is needed.

This trial does not qualify delivery to other recipients, a raw 1 MiB upload,
native installed-client/UI end-to-end behavior or isolation through a distinct
registered second installation. A second local identity was rejected at the
installation-signature boundary; it is not evidence for that latter case.
See the [earlier activation audit](central-oauth-activation-2026-10-21.md) for the
other providers and their separate remaining work.
