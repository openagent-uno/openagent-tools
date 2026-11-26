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

The filesystem tool `attach_file` reads one regular file from its configured
roots and returns an embedded binary file to a runtime that supports session
attachments. It allows up to 32 MiB. On macOS, an operating-system denial
returns `filesystem_access_denied` and the resolved requested path. A native
host can use that response to ask the user for access to the specific item.

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

On macOS a shell server started without an explicit environment (for example
inside an App launched from Finder or the Dock, which only inherits launchd's
`/usr/bin:/bin:/usr/sbin:/sbin`) asks the user's interactive login shell for
`PATH` once, with stdin closed and a five-second limit, and puts those entries
first. If the probe fails it appends the existing Homebrew and `/usr/local/bin`
directories. Only `PATH` changes. Set `OPENAGENT_SHELL_LOGIN_PATH=0` to keep the
inherited value; an environment passed explicitly to `ShellServer` is never altered.

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

## Direct terminal and preview on a task computer

The optional Linux guest surfaces in `openagent-shell 1.0.0b5` require a dedicated
guest account and a capability transport that authenticates the human account,
network, device and task allocation on every call. Configure the guest capability
host with `OPENAGENT_TASK_SURFACE_WORKSPACE=/srv/workspace`. The optional
`OPENAGENT_TASK_PREVIEW=18285:/` selects one exact guest loopback port and path.
An ordinary shell installation exposes its existing catalog by default.

The shell manifest advertises available operations in the `openagent/task-surfaces`
metadata on `shell_exec`. A trusted host mounts the exact assigned computer
and uses the originating capability's app-only siblings through
`call_source_tool`. Grant terminal observation, input and preview separately.
Check membership, lifecycle epoch, connection generation and grants before the
operation and before returning any data. A client-supplied terminal ID identifies
a process within an authorized assignment.

| Guest operation | Result |
| --- | --- |
| `task_surface_open` | Start the interactive PTY in the configured workspace or reattach to its existing session. Opening requires input authority. |
| `task_surface_attach` | Attach to a terminal that already exists with read authority. |
| `task_surface_read` | Read up to 32 KiB from a byte cursor. The latest 256 KiB are retained. Read the next page from `next_cursor`. A truncated prefix advances `offset`. `output_base64` preserves exact bytes. |
| `task_surface_input` | Queue one input of up to 4 KiB for the exact PTY. A request UUID binds to the exact input. Reusing it with different bytes returns an error. The caller can observe the command's output separately. |
| `task_surface_preview` | Return a bounded static HTML or PNG representation from the configured guest endpoint. The host supplies its configured endpoint for an exact match. The reader sends no cookies and follows no redirects. |

The Linux PTY lives inside the assigned guest. Closing a client or replacing
the capability-host process preserves a running shell. A normal shell exit
records its exit code and last output on the guest disk. A lost guest process
reports an unknown outcome. Control resumes only after enrollment and current
authorization. HTML previews retain text and structural elements. Render them
in a sandboxed frame with an opaque origin. The enrolled guest browser and
desktop viewer provide interactive access to applications.
