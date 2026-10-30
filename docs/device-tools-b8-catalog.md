# Device Tools beta8: exact published MCP catalog

`openagent-device-tools==1.0.0b8` updates only the captured discovery catalog.
Native source stays at `0.1.5` and the browser source stays at `3.0.0`; their
implementation and locked dependencies are unchanged from Tools beta5.

The previous capture mixed earlier Zod emission and handwritten advanced tool
schemas with the final SDK `1.32.2` / Zod `4.6.7` runtime. An actual release
bundle therefore exposed different integer bounds, references and object/array
constraints. Its JSON was rejected by the strict release catalog comparison.
The native raw capture also omitted the computer action classifier that the
public manifest added at import time.

The new snapshot comes from actual MCP initialize/tools-list responses of the
frozen, independently built runtime, adapted by the public capability-host
protocol adapter. The eight browser host source/lock files match the committed
source byte for byte. Native and browser identities, versions and instructions
are checked before capture. No tool action, browser page, native UI, clipboard
or audio operation runs during the capture. No runtime token or resource
generation is present in the recorded tool metadata.

The snapshot includes all 15 native and 25 browser definitions, complete input
schemas and argument classifications. Release checks must compare the complete
materialized contract; they must not drop bounds, `additionalProperties`,
`uniqueItems`, references or metadata to make an old capture pass. A regression
checks raw/materialized equality, and an optional owned-bundle integration
fixture checks the entire advertised contract against the real SDK response:

```sh
OPENAGENT_DEVICE_TOOLS_PROBE_BUNDLE=/absolute/path/to/owned/bundle \
  python -m pytest tests/test_device_tools.py
```

The browser fixture is metadata only and does not launch Chromium. The optional
release uses a new Device Tools wheel and reuses the six other independently
versioned Tools beta5 wheels without rebuilding or changing their public bytes.
Each reused artifact retains its original source/release provenance in the new
manifest. Publication and signed product bundles remain separate gates.
