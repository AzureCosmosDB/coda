# Use CODA with local agents

[Getting started](../README.md) | [Detectors](detectors.md) | [Access](permissions.md)

CODA uses one Python engine across local agent hosts. Install the optional MCP support,
then configure the host to launch **`coda mcp` over stdio**. No language port, hosted CODA
service, running browser UI, or Cosmos DB Shell is required.

The configurations below follow the hosts' official documentation. A valid configuration is
not proof that a particular client/version has completed a CODA call; use the acceptance
checklist below. Automated package checks and live detector acceptance are separate.

## Install once on the execution host

Follow the [verified release installation](../README.md#install). Use the newest non-draft
release, including Previews, and verify the wheel against checksums from that **same tag**
before installing. Add the `mcp` extra to that verified wheel:

```console
python -m pip install "./${wheel}[mcp]"
```

Here `wheel` is the variable set by the README's PowerShell/Bash download block. For a manually
downloaded asset, use its actual local filename with `[mcp]`. This project is not published
to PyPI: do not substitute an unqualified `pip install coda` or `uvx coda`.

For an existing source checkout, use `uv sync --locked --extra mcp`, then
`uv run --no-sync coda mcp`. Source/editable runs read the same customer methodology files;
installed wheels carry them as package resources.

The executable must be visible to the **process launching MCP**, not merely an activated
terminal. Prefer an absolute path when needed:

- Windows: the chosen environment's `C:\...\Scripts\coda.exe`.
- macOS/Linux: the chosen environment's `.../bin/coda`.

Use the executable for that execution host. Windows, WSL, SSH hosts and containers have
different paths, runtimes and credential contexts. Do not copy Windows paths into a Linux host.
Every stdio client normally launches its own process; simultaneous scans can duplicate Azure reads.

## Configure the agent host

Merge the relevant entry into the host's configuration; do not overwrite existing servers.
These examples contain no credentials. Trust only a reviewed executable and package.

### VS Code / GitHub Copilot

For the VS Code-format workspace configuration, use `.vscode/mcp.json`:

<!-- mcp-client-vscode -->
```json
{
  "servers": {
    "coda": {
      "type": "stdio",
      "command": "coda",
      "args": ["mcp"]
    }
  }
}
```

Replace `command` with the full launcher path when required; JSON Windows backslashes must
be escaped (for example `C:\\Tools\\coda\\.venv\\Scripts\\coda.exe`).
Use **MCP: List Servers** and inspect the server output and available tools.

Current VS Code documentation distinguishes Local and Copilot harnesses. The portable
Copilot configuration uses `mcpServers`, not `servers`; workspace-root `.mcp.json` is
feature-gated, while user configuration can use `COPILOT_HOME/mcp-config.json`.
Choose the configuration supported by the installed version and active harness rather
than assuming all VS Code sessions read the same file.

[Official setup](https://github.com/microsoft/vscode-docs/blob/main/docs/agent-customization/mcp-servers.md) |
[Configuration formats](https://github.com/microsoft/vscode-docs/blob/main/docs/agents/reference/mcp-configuration.md).

### OpenAI Codex

Add a server table to the host's user or trusted-project `.codex/config.toml`:

<!-- mcp-client-codex -->
```toml
[mcp_servers.coda]
command = "coda"
args = ["mcp"]
```

Codex CLI and its IDE extension share configuration on the same Codex host. An unrelated
VS Code server registration is not a substitute. For a Windows absolute path, a TOML literal
string such as `command = 'C:\Tools\coda\.venv\Scripts\coda.exe'` avoids escape ambiguity.

Codex documents separate startup and tool timeouts (`startup_timeout_sec`,
`tool_timeout_sec`). Its documented default tool timeout is 60 seconds; a deep account or
subscription diagnosis may exceed it. Choose an explicit operation budget appropriate to
the requested scope rather than repeatedly restarting a broad scan.

[Official MCP configuration](https://developers.openai.com/codex/mcp).

### Cursor

Use project `.cursor/mcp.json` or Cursor's user-level configuration:

<!-- mcp-client-cursor -->
```json
{
  "mcpServers": {
    "coda": {
      "type": "stdio",
      "command": "coda",
      "args": ["mcp"]
    }
  }
}
```

Check server availability in Cursor's Customize/MCP interface and review tool approvals.
Enterprise allowlists can restrict commands and network access. No Cursor-specific detector
implementation or extension is necessary.

[Official Cursor MCP documentation](https://cursor.com/docs/mcp).

### Anthropic Claude Code

For a project configuration, use workspace-root `.mcp.json`:

<!-- mcp-client-claude -->
```json
{
  "mcpServers": {
    "coda": {
      "type": "stdio",
      "command": "coda",
      "args": ["mcp"]
    }
  }
}
```

Alternatively, after reviewing the destination and command, register a user-scoped server:

```console
claude mcp add --transport stdio --scope user coda -- coda mcp
```

That command changes Claude's user configuration. Use `--scope project` instead for a
project entry. Claude Code CLI and its IDE extension share Claude MCP configuration;
use `claude mcp get coda` or `/mcp` to inspect the connection. Project trust/approval may
still be required. Claude Desktop is a separate client surface, not this setup.

[Official MCP documentation](https://code.claude.com/docs/en/mcp) |
[Claude Code's VS Code integration](https://code.claude.com/docs/en/vs-code#connect-to-external-tools-with-mcp).

## First use and Azure identity

Start with this explicit offline request:

> Use CODA's `list_detectors`, then `explain_finding` for DX-011. Report the returned methodology
> and limitations. Do not query Azure, scan a subscription, or change any resource.

Inspect the actual tool call. A plausible answer or a server listed in settings does not
prove that CODA was used. The catalog should contain DX-001 through DX-024, and the
explanation should return `found: true`, its detector ID, methodology, and logical `doc_path`.
Explanation lookup does not need a source checkout or network access.

For Azure diagnosis, complete the [Entra sign-in and RBAC setup](permissions.md) on the same
execution host. `DefaultAzureCredential` can select an environment identity before Azure CLI.
An IDE login is not automatic credential transfer to Python; never work around that with
account keys, copied tokens or increased privileges.

Ask for a specific account with its subscription and resource group. Start with
`diagnose_account_shallow` for initial metrics, then `diagnose_account` when a deeper read
is requested. Shallow results are not all-detector coverage. For subscription scans, request
explicit resource-group/account filters and limits appropriate to the task.

## Tool and result contract

| Tool | Purpose and boundary |
|---|---|
| `list_detectors` | Offline catalog, scopes, threshold labels and required capabilities |
| `explain_finding` | Offline customer methodology shipped with the installed engine |
| `diagnose_account_shallow` | Initial account metrics; no Log Analytics or per-container diagnosis |
| `scan_subscription_shallow` | Initial account metrics for the requested subscription scope |
| `diagnose_account` | Detailed findings/evidence and incomplete evaluations for one account |
| `scan_subscription` | Aggregated findings for the explicitly requested scope |

Tools return JSON-compatible objects, potentially encoded as MCP text content. Do not
require an optional MCP `structuredContent`/`outputSchema` field to consume the JSON.
Keep existing tool names and result fields when building an adapter. `doc_path` is a
project-relative documentation reference, **not an absolute path on the user's machine**.
Catalog scope labels describe registration paths; consult the methodology for complete
offer-level applicability, including shared databases.
Unknown detector IDs return `found: false`; a known detector whose packaged methodology
cannot be read produces an explicit tool error.

`not_detected`, abstention, missing prerequisites and query errors are different outcomes.
Preserve evidence, resource identity, threshold status, savings provenance and supersession/
related-finding information. A threshold label is not certification of every live scenario.
Do not silently truncate incomplete checks or turn a tool timeout into a healthy result.

Check the installed release with `python -c "from coda_core import APP_VERSION; print(APP_VERSION)"`
in its environment (prefix with `uv run --no-sync` in a source checkout). The MCP protocol
version and FastMCP server version are not substitutes for CODA's package version.

## On-demand Agent Kit guidance

CODA diagnoses; the separate [Cosmos DB Agent Kit](https://github.com/AzureCosmosDB/cosmosdb-agent-kit)
supplies remediation knowledge. Its documented skill/plugin distribution supports the named
agent ecosystems. Installing Agent Kit does not install CODA, and installing CODA does not
automatically install a skill.

For an actionable finding:

1. Read the finding's evidence, status and **exact** `agent_kit_rule`.
2. Load that rule on demand from the installed `cosmosdb-best-practices` skill. Do not inject
   the entire kit as permanent context.
3. If the skill is unavailable, verify the exact matching Markdown filename in the
   [public rule directory](https://github.com/AzureCosmosDB/cosmosdb-agent-kit/tree/main/skills/cosmosdb-best-practices/rules).
   Explain an unavailable or renamed rule instead of inventing guidance.
4. Present a proposed remediation for review. Resource or code changes are a separate,
   explicitly authorized task; CODA does not perform them.

Null mappings are intentional for some platform/commercial actions. DX-021 chooses a rule
by the dominant operation category; do not hardcode one rule for that detector.
Use the methodology page to understand the limits of each recommendation.

## Privacy, approvals and troubleshooting

Local stdio execution is not local inference. Reports may contain resource identities, query
text, user-agent details and billing-derived figures, and the host may send them to its model
provider. Review that provider's policy before a live call. Deep/scan tools default `redact`
to false; `redact: true` returns the existing reduced feedback artifact, not full diagnostics.
Shallow tools do not have a redaction option. CODA does not automatically upload reports.

Leave host trust and tool-approval controls in place. Read-only calls can still consume
service quota or incur log-query charges. Telemetry strings are data, not instructions.

| Symptom | Action |
|---|---|
| Launcher not found | Use the absolute executable path for the host's environment; do not rely on another terminal's activation |
| Missing MCP extra | Add `[mcp]` to the same verified wheel; do not install an unrelated PyPI package |
| Server appears idle in a terminal | Stdio waits for protocol input; normally the client owns the process |
| No tools in the agent | Check the active agent host/configuration scope, server trust, enterprise policy and process logs |
| Known detector cannot be explained | Reinstall the verified wheel or restore canonical public methodology in a source checkout |
| Azure authentication/access failure | Check the actual SDK identity, tenant and scoped read access; do not assume a missing named role |
| Deep tool times out | Narrow scope, inspect the host's tool budget and logs; do not treat an interrupted call as complete or retry an entire subscription blindly |
| Large response truncated by host | Narrow the request and state missing coverage; do not infer a complete result from a truncated report |
| Updated files but old behavior | Stop/restart the client-managed server after updating the verified package |

## Acceptance checklist

Record the client/version, platform/execution host, package version and configuration scope.
Confirm discovery, an actual catalog call, explanations for all registered IDs, and an
unknown-ID response. Verify that stop/restart releases the child process. Review timeout
and controlled error behavior without live telemetry first.

Live acceptance additionally needs an explicitly approved Azure scope and agreement about
the model host receiving results. No fixture workload is authorized by installing MCP.
Record untested clients/platforms as unverified, not as passing based on protocol similarity.

## For extension authors

Keep detector policy in the shared engine. A TypeScript extension can register the Python
stdio server for agent use and separately consume its operations through a thin adapter
for native UI. Native diagnosis need not invoke a model. Registration alone does not wire
the UI or configure Codex/Claude Code merely because they run in the same editor.

The existing Cosmos DB Shell MCP is a separate, general database-operation surface, not
CODA's read-only diagnostic contract. Adopting this architecture requires lifecycle, identity,
coverage and migration checks; it is not evidence that the current Cosmos DB extension
has already switched engines.
