# OpenAgent media inspector 0.2

A deterministic tool for hosts whose reasoning model accepts text and images.
The host authorizes an original or an exact public sharing URL; neither service receives
provider credentials, cookies or account identifiers. Keep originals in the host store. This tool makes a bounded preview, not a validation of a
document, signature, payment, or legal claim.

`POST /v1/inspect` accepts a raw body of 1–5,000,000 bytes and a MIME
`Content-Type`. It returns `{version:"1",status,content}`. Content is standard
MCP text and image blocks; `status` is `read`, `partial`, or `unreadable`.
The text may itself be untrusted document content. `GET /health` reports the
contract version. Requests have no persistent state, and overload is explicit.
Run it as a private non-root service with no outbound network access. Do not
expose the decoder on an internet ingress or treat it as an auth service.

Images are resized, animated images use the first frame, PDFs expose text and
page previews (first four pages), video exposes sampled frames within the first
60 seconds, and local speech transcription uses at most 60 seconds of decoded
audio. Transcripts can be wrong, especially names and numbers. Plain UTF-8
files, including CSV/JSON, expose bounded text. DOCX, XLSX and PPTX expose
selected text or cached values without executing macros or formulas. Unknown
binaries, protected documents and unavailable content are
reported unreadable without executing or extracting arbitrary archives.
Decoder work has a subprocess deadline and bounded concurrency. Requiring no
network access at runtime prevents media files from fetching remote resources.
The speech model is fixed at build time; decoding never downloads it.


## Credential-free shared media

The optional **link gateway is a separate deployment**, using this same image with
`OPENAGENT_MEDIA_DECODER_URL` set by the operator to the private decoder origin.
It accepts only `POST /v1/inspect-url` with `{"url":"https://..."}`. The host must
bind that URL to an authorized source; this endpoint is not an authorization service.
The gateway cannot serve byte inspection endpoints and never decodes downloaded content.
The decoder must retain deny-all network egress; give the gateway only DNS, public
HTTPS and its fixed private decoder destination. Neither service has public ingress,
credentials, service-account tokens, persistent storage or a writable root filesystem.

Supported shares: Google Drive `/file/d/<id>` (normalized to the usercontent download
endpoint), Dropbox `/s/` and `/scl/fi/` (`dl=1`, preserving share keys), and public
WeTransfer download/short links. WeTransfer returns a single media file; archives,
expired links, login/confirmation HTML and protected shares fail closed. No browser,
cookies, credential fallback or arbitrary archive extraction is used.

Every hop remains HTTPS on port 443 within the original provider allowlist, with
hostname TLS verification and a connection pinned to a DNS answer verified public.
Mixed private/public DNS, userinfo, arbitrary hosts and cross-provider redirects
are rejected. Downloads have a 150,000,000-byte streaming limit, five redirect limit,
10-second socket budget and 120-second total deadline (125-second process kill,
including DNS). Types must be video/audio or octet-stream with a supported media
signature; response bodies are not logged. Provider failure returns explicit
unreadable coverage, with no inference about the file.

The decoder's additive `/v1/inspect-video` accepts those bytes and rejects unknown
or greater-than-180-second durations. It returns the same version-1 MCP content
contract: up to five frames, including the opening seconds and final second,
duration/byte coverage, and local timestamped multilingual machine transcription
(auto-detected language, including Italian, Spanish, Portuguese, German, French
and English). Sampling never proves every moment. A missing audio track or unavailable
transcript remains explicit. The existing `/v1/inspect` keeps its 5 MB / 60 s limits.
The model is the existing checksum-pinned multilingual tiny model, fetched only
at build time. Decoder wall time is at most 185 seconds; concurrent requests are
bounded to two. Hosts should allow 325 seconds for the combined URL request.

## Independent release procedure

1. Run `PYTHONPATH=packages/media-inspector/src python -m pytest packages/media-inspector/tests` in an isolated environment with `requirements.lock` installed.
2. Bump this package only, commit source/tests/docs, and build a wheel from that clean
   source into a new empty output directory with `python -m build --wheel`.
3. Publish an immutable `media-inspector-v<version>` tag/release with the wheel and
   a manifest containing source SHA, artifact SHA-256/size and qualification scope.
4. Build the package Dockerfile for the deployment architecture from the exact tagged
   source; publish an immutable OCI tag and record its registry digest. Consume only
   that digest. Source tests, public artifact checks and live-provider acceptance
   are distinct evidence; never promote an untested dirty snapshot.
