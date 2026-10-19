# Microsoft exchange diagnostic checkpoint — 19 October 2026

The image-only rollout passed at **08:43:13 UTC**: one Ready writer, zero restarts, **11 configured providers**, health/readiness **200** and unsigned protected requests **401**. The [sanitized receipt](qualification-2026-10-19-diagnostics.json) binds the source, binary, raw scan and deployment evidence.

Tools source `645e0484c3ec40d4965de038be8d3a258ec44aac` adds closed diagnostic labels for an initial Microsoft OAuth exchange failure. The log contains only provider, stage, reason and provider-error enums. It exports no tokens, raw scope strings, account identifiers, provider bodies or arbitrary messages. Scope acceptance and permission validation remain unchanged and fail closed.

The focused `auth`/`oauth` tests, associated vet and a single static Linux authentication-binary build passed remotely with Go 1.26.9. The 176 source files were unchanged. Assembly retained the six qualified parent layers and appended only `/connector-auth`; all seven compressed hashes and uncompressed diff IDs were verified. Trivy 0.72.0 passed with **0 vulnerabilities and 0 secrets** under the existing HIGH/CRITICAL, ignore-unfixed policy, without new exceptions. The digest-only upload wrote no tags.

Fresh UID/resourceVersion/spec tests and server dry-run preceded an image-only compare-and-swap. Provider bytes, projected Secret references, metadata volume, event key and identities were preserved. The temporary Go worker was deleted with UID/resourceVersion preconditions and confirmed absent; scan and packaging/upload execution also ended. The independent receiving QA pod was preserved.

This release step made **zero provider API calls** and obtained **no consent or grant**. The public SDK18 release is unchanged. Google Testing restrictions and all pending real-provider/receiving-host acceptance boundaries from the [activation checkpoint](qualification-2026-10-19-activation.md) remain. The checked-in bootstrap still contains zero provider rows and must not replace the live operator overlay.
