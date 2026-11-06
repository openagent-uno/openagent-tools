# Using Tools independently and through Core

Read [components](COMPONENTS.md) and [agnostic architecture](AGNOSTICISM.md).
Install the exact compatible package set from a reviewed wheel/binary manifest
into an isolated environment. Python packages require Python 3.11+; browser and
native sidecars have separate runtime/artifact requirements.

## Direct Python tool

Install `openagent-tool-protocol` and `openagent-filesystem`, then run
[examples/filesystem.py](../examples/filesystem.py). It writes one synthetic file
inside an owned temporary directory and reads it through FilesystemServer with
an explicit allowed root. It closes the provider and removes that directory.
It starts no model, server or network listener.

From a source checkout on a POSIX shell:

```sh
PYTHONPATH=packages/tool-protocol/src:packages/filesystem/src \
  python3 examples/filesystem.py
```

The result contains `hello from a generic tool`. A direct tool method is not
authentication: the host must authorize any operation exposed to an untrusted caller.

## MCP stdio

After installing the matching package, configure an MCP client to launch one of:

| Capability | Console entry point |
| --- | --- |
| Filesystem | `openagent-filesystem-mcp` |
| Editor | `openagent-editor-mcp` |
| Shell | `openagent-shell-mcp` |
| Web search | `openagent-web-search-mcp` |

The first three can also be started as `python -m openagent_filesystem`,
`python -m openagent_editor`, `python -m openagent_shell`. The MCP client owns the
stdio pipes and initialization/tools-list/call sequence. Do not treat protocol
stdout as a human terminal. Set an owned working directory and host policy;
the convenience filesystem entry point does not supply a user/tenant boundary.
See [independent transport fixtures](../tests/test_independent_mcp.py).

## Register tools with an agent runtime

The host creates a CapabilitySource/executor adapter or configures an explicitly
owned MCP source, then registers it with Core's public CapabilityCatalog.
Bind actor/authority/audience, exact destination, generation and leases in trusted
code. The model discovers opaque references and calls the same generic tools.
No consumer-specific import or standalone server dependency belongs in Tools.
For an engine-free tool host, use the separate `openagent-capability-host`
package from Core. For the standalone product facade, use `packages/host-tools`
in `openagent`; neither requires copying these providers.

## Execute code in an explicit backend

`openagent_execution.ProcessCodeExecutor` accepts `backend`,
`python_executable`, `bridge_transport`, `isolated`, `environment` and optional
`workdir`. Select `LocalBackend`, `DockerBackend` or `SSHBackend` explicitly.
The source validates transport/backend compatibility; remote execution requires
the filesystem bridge and an owned workdir. A host provisions the sandbox and
injects only the required environment. Close the executor to release its owned
commands/backend. [Executor source](../packages/execution/src/openagent_execution/executor.py)
and [execution fixtures](../tests/test_execution.py) define exact contracts.

## Native device and browser capabilities

Use `openagent_device_tools.discover_sidecars` and the reviewed sidecar manifest
to select compatible binaries/runtime inputs. Register them through the public
host adapter; do not use consumer-local copies. The browser sidecar speaks MCP
and controls a dedicated browser over CDP. Browser download/provisioning,
system permissions, device consent and operator approvals are separate actions.
See [browser](browser-advanced.md), [native controls](native-controls-advanced.md)
and [native accessibility](native-accessibility.md). Source tests are not a signed
installer or live GUI acceptance.

## Provider connectors

Go hosts import `github.com/openagent-uno/openagent-tools/packages/connectors`.
Create the shared Runtime, list Tools for an already authorized Binding and
Invoke an exact bound operation. The host owns account lookup, grants,
credential resolution and durable effects; arguments cannot choose them.

Python hosts use `openagent-connectors` and an exact verified native
`openagent-connector-runner` from the same release. Preserve stdin/stdout IPC
separation of credentials and arguments. For full SDK, broker, build and rollout
contracts read [connectors](../packages/connectors/README.md) and
[auth operations](../deploy/connector-auth/README.md). A catalog entry, optional
OAuth registration and actual provider acceptance are separate facts.

## Start an independent MCP server

Use [examples/mcp-server](../examples/mcp-server/README.md) as the maintained
stdio scaffold. It is installed independently and does not require the engine.
Its hello-tool regression uses the actual MCP initialize/list/call protocol.

- [Desktop execution, live media and native artifacts](desktop-tools.md)
