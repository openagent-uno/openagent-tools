# OpenAgent media inspector 0.1

A deterministic tool for hosts whose reasoning model accepts text and images.
The host authorizes and retrieves an original; the inspector never receives a
provider credential, path, URL, or account identifier. Keep the original in
the host's store. This tool makes a bounded preview, not a validation of a
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
