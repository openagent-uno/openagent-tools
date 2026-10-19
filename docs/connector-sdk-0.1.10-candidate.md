# SDK 0.1.10 patch qualification

SDK 0.1.10 is a source candidate awaiting canonical remote qualification and publication. It includes the bounded Postiz provider-failure propagation already reviewed on main. The catalog remains 114 official connectors plus Custom MCP, with the same 315 read and 82 action operations, schemas, permissions and authentication contracts as SDK 0.1.9.

Postiz failures preserve only the existing finite error kind and validated HTTP status. Raw messages, provider request identifiers, headers, credentials and response bodies remain redacted. Unknown kinds and mismatched statuses retain the generic failure. The synthetic no-expiry OAuth fixture also verifies the fixed integrations endpoint and raw Authorization credential contract; it does not prove account entitlement or live provider access.

The canonical qualifier retains every SDK 0.1.9 cohort, source Python catalog parity, privacy, native metadata and acquisition guard. Publication requires sequential tests/race, vet, vulnerability checks, six-platform runner/auth builds, the Python wheel, source provenance and checksums, and Linux native/installed qualification. Cross-compilation does not establish native macOS or Windows execution.

No provider calls, new grants, account trials or subscriptions are part of this release qualification. SDK 0.1.9 and its immutable receipts remain historical. A product must explicitly adopt this version; publishing this SDK does not update an installed server or CLI.
