# Web-search browser resource lifecycle

The independent `openagent-web-search-mcp` package owns its extraction browsers.
The host owns process supervision and installs an exact versioned archive.
Browser cookies or profiles owned by other registered tools are not cleanup
targets for this package.

Concurrent extraction previously checked an empty browser map before awaiting
launch. Several callers could each launch Chromium and overwrite the same map
entry, leaving earlier browsers outside pool shutdown. Navigation and parsing
errors also bypassed context cleanup. A batch's detached timeout could report
completion while extraction continued with those resources.

Version `1.0.0-beta.3` coalesces launches by browser type, drains pending launches
during shutdown, closes every request's context in `finally`, and bounds browser
extraction to two concurrent jobs per extractor. Both HTTP/2 fallback contexts
and original contexts retain independent cleanup. Batch completion includes
extraction cleanup; HTTP/navigation timeouts remain operation-specific.

The regression fixtures use neutral synthetic pages and identities. They exercise
concurrent acquisition, shutdown during launch, navigation and fallback failures,
batch completion and concurrent context limits. The existing public-address and
redirect refusal tests remain required. Installed real-browser qualification and
host adoption are separate from source test results.

For a memory-pressure incident, retain kernel and service evidence privately and
distinguish an OOM-killed browser child from the host agent process. A supervisor
configured to stop the whole unit on any child OOM can turn a recoverable tool
failure into a full agent outage. Configure and verify host policy separately;
this tool does not change service-manager or machine memory settings.
