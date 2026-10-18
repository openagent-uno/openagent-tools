# OneDrive and SharePoint source candidate

Status: implemented in the working source for review; **not qualified or published**. The public SDK0.1.7 remains the previous22-connector release. These two additions extend the previous22-connector base to24 before the separately reviewed definition batches, excluding Custom MCP. No provider app, consent, tenant grant or production configuration is changed by this source work.

The adapters share the existing delegated Microsoft Graph confidential OAuth flow, PKCE, `/me?$select=id` account verification on exchange and refresh, and host-owned credential storage. Each connection binds one account and an optional selected site/drive independently. No calendar, document editor, sync service or domain-specific application is implemented.

## Read-only operations

All tools use the `files` capability, typed closed argument objects and one provider attempt per phase. No raw operation or write tool is available.

| Provider | Tools | Graph resources |
| --- | --- | --- |
| `onedrive` | `files.onedrive.drives.list`, `.drives.get`, `.items.list`, `.items.get`, `.items.content` | `/v1.0/me/drives`, `/v1.0/drives/{bound_drive_id}`, its root/folder children, item metadata and content |
| `sharepoint` | `files.sharepoint.sites.search`, `.sites.get`, `.drives.list`, `.drives.get`, `.items.list`, `.items.get`, `.items.content` | `/v1.0/sites?search=...`, the bound site and its document libraries, and the bound library's drive items |

OneDrive discovery lists existing account drives with `/me/drives`. It never probes `/me/drive`, whose documented behavior can provision a licensed user's drive. SharePoint discovery searches authorized sites; a site-only binding then lists its document libraries. The host selects and persists the site/drive pair from these authorized discovery results before resource operations can execute. The adapter does not claim to prove membership from an arbitrary host-supplied pair: the host must derive the pair from the selected site's library list, reauthorize changes locally, and replace the entire binding when account/site/drive changes.

`items.list` accepts optional `parent_id` (omitted means drive root), `top`1–100 and an opaque `page_token`. `items.get` and `items.content` require `item_id`. `sites.search` accepts a bounded non-wildcard query. Account, tenant, drive, site, origin, URL and headers cannot be supplied in model arguments. Opaque IDs are bounded and escaped as single path segments.

## Authorization and binding

Minimal requested scopes are:

- OneDrive: `offline_access User.Read Files.Read`.
- SharePoint: `offline_access User.Read Sites.Read.All`.

The OAuth layer also recognizes Microsoft's exact resource-prefixed form and stores canonical short names. Endpoint-documented stronger delegated grants are recognized for read admission only; no grant is requested or widened automatically. Existing Outlook providers still reject unrelated Files/Sites scopes. `Sites.Read.All` is broad delegated site access and must be presented explicitly at consent. SharePoint site APIs are work/school APIs; a personal Microsoft account is not a substitute. Tenant policy can still require administrative approval.

`Sites.Selected` and other Selected permissions are **not supported by this initial subset**. They require explicit resource assignments and do not support the same site search contract; the adapter neither creates assignments nor requests `Sites.FullControl.All` to assign itself access. A Selected-only connection has no exposed tools. No application-permission/client-credentials flow, sovereign cloud or fallback to broader scopes is implemented.

Host-owned `Connection.Config` is a closed object:

```json
{"drive_id":"opaque-drive-id","site_id":"tenant.sharepoint.com,site-collection-guid,web-guid"}
```

`site_id` is required for a SharePoint drive binding and optional for OneDrive. Empty configuration permits only account-drive/site discovery. A site-only SharePoint configuration permits site metadata and library discovery. OneDrive Business can additionally bind `download_host` to the exact SharePoint hostname derived by the host from the selected drive's Graph metadata. If a site ID is supplied, that exact hostname is authoritative and a different `download_host` is rejected. `download_host` accepts only the global `tenant.sharepoint.com` form, never an arbitrary HTTPS endpoint. It is not an OAuth credential.

Changing the selected binding requires host authorization, not a model argument or implicit cross-site retry. Every invocation checks the enabled connection, workspace, provider, bound connection principal, current scope and verified external account. Continuations are HMAC-authenticated using the connection credential and its redacted metadata/version. They bind the connection, account, provider, canonical configuration, operation, path, query and page size; each next link must retain the fixed Graph origin and finite query contract. No automatic complete traversal is performed.

## Content and response boundaries

Metadata responses are whitelisted. Temporary download URLs, provider web URLs, permission objects, arbitrary nested fields and remote items are not returned. A safe `sharepoint_host` hostname may be returned for host binding selection. Cross-drive parent references and mismatched object IDs are rejected. JSON parsing rejects duplicate keys and bounds size, depth and node count.

Graph's content endpoint returns a short-lived preauthenticated redirect. The adapter accepts exactly one302 from the bound Graph item and consumes its location internally. It makes at most one additional GET through a separate anonymous transport, with no Authorization, Cookie, Referer, ambient proxy or client certificate. The only destinations are HTTPS/default443 hosts under the strict `.files.1drv.com` boundary or the exact trusted SharePoint host bound above. IP literals, alternate clouds, userinfo, fragments, second redirects and suffix lookalikes are rejected. The signed URL is never returned, logged, added to a cursor or included in an error.

A complete response must be HTTP200 and at most2MiB. Oversize or partial content is rejected rather than reported as a successful complete file. UTF-8 data without NUL is returned as text; other bytes use base64. Results include content type, byte count and SHA256, with no execution of file content. Unsupported download host families fail closed. Graph and download phases share one cancellable30-second deadline. Quota and other provider failures are not retried automatically; public errors expose only finite status/kind through the shared runtime's safe error contract.

## Qualification still required

The source fixtures cover finite inventory/scopes, closed binding and bootstrap routes, cursor substitution, cross-drive/site responses, metadata URL stripping, anonymous transport isolation, redirect and credential leakage, UTF-8/binary content, size bounds, cancellation, one-attempt quota failures, PKCE/account verification and runtime error sanitization. Focused provider, OAuth and runtime fixtures passed on the bounded Linux source worker on 18 October 2026. This is source qualification; the canonical release gate and real Microsoft consent remain separate.

Before release: run the focused providers/OAuth/runtime fixtures remotely, then the canonical SDK suite and release matrix once. Qualify actual delegated OneDrive and SharePoint accounts and host selection/persistence, including Business download-host behavior, pagination and real quota errors. Product fallback catalogs, acquisition pins, logos, own-app UI and common-broker activation remain separate integration work. No live OAuth or provider read is asserted here.

## Primary contracts reviewed 2026-10-18

- [List drives](https://learn.microsoft.com/en-us/graph/api/drive-list?view=graph-rest-1.0), [get drive and provisioning behavior](https://learn.microsoft.com/en-us/graph/api/drive-get?view=graph-rest-1.0).
- [List folder children](https://learn.microsoft.com/en-us/graph/api/driveitem-list-children?view=graph-rest-1.0), [get drive item](https://learn.microsoft.com/en-us/graph/api/driveitem-get?view=graph-rest-1.0), [download content and unauthenticated redirect](https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0).
- [Get site](https://learn.microsoft.com/en-us/graph/api/site-get?view=graph-rest-1.0), [search sites and Selected limitation](https://learn.microsoft.com/en-us/graph/api/site-search?view=graph-rest-1.0), [Selected permissions and resource assignments](https://learn.microsoft.com/en-us/graph/permissions-selected-overview).
- [Delegated authorization-code/PKCE flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow), [Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference).
