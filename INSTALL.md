# INSTALL.md — LedgerAgent Manual Install (All Clients)

Portable core works with zero shim files. Five steps below install on any Skills+MCP client.

## 1. Install Skills
Copy `skills/setup`, `skills/plan`, `skills/run`, `skills/wallet`, `skills/deposit` (each with `SKILL.md`) to your client's skills directory. For T1 shims, see `ledger-mcp install --print --format=skills`.

## 2. Register MCP Server
```json
{
  "mcpServers": {
    "ledger-mcp": { "command": "./bin/ledger-mcp", "args": [] }
  }
}
```
Only `${PLUGIN_ROOT}` / `${PLUGIN_DATA}` expand, and only in args/env/cwd (R8.2). Command is one token `./bin/ledger-mcp` (R8.1).

For any target: `ledger-mcp install --print --target=<name>` emits the block.

## 3. Wire AGENTS.md Persistent Memory
Run `setup_init_memory` via MCP, or manually insert:
```
ledger-mcp install --print --format=agents-md
```
This emits the idempotent `<!-- LedgerAgent:memory:start --> ... <!-- LedgerAgent:memory:end -->` block. The server creates `${PLUGIN_DATA}/memory/` with 5 markdown files and wires `AGENTS.md` without touching other content. If `CLAUDE.md`/`GEMINI.md` exists, add `@AGENTS.md` pointer.

Memory lives in `${PLUGIN_DATA}/memory/` (R8.3): `profile.md`, `opportunities.md`, `active_plan.md`, `execution_log.md`, `lessons_and_incidents.md`. Each capped 32 KB; files >24 KB rotate to `archive/YYYY-MM.md` (R8.6).

## 4. Attach Agent Reach Sensing Channels
Agent Reach state isolates in `~/.agent-reach/` (never user's primary browser). Default: `github`, `youtube`, `bilibili`, `v2ex`, `web`. Optional: `x`, `reddit`, `xiaohongshu`, `linkedin`, `boss`, `xueqiu`. Install via `agent-reach setup` and `agent-reach add <channel>`; verify with `agent-reach doctor --text`. The server wraps them read-only with `untrusted:true`.

## 5. Verify Agent Browser Binary / Headless Runtime
Install: `npm i -g agent-browser && agent-browser install`. Verify isolated profiles under `${PLUGIN_DATA}/browser-profiles/` (never user's Chrome). Check with `ledger-mcp doctor` and `browser_doctor`. Browser uses `snapshot -i` with `@eN` refs and domain allowlist enforcement.

## Verify
```
ledger-mcp doctor
ledger-mcp setup_doctor  # via MCP tool setup_doctor
```
Checks containment, manifest schema, keychain, broker socket perms, AGENTS.md wiring, memory size, ledger chain, agent-reach provenance, agent-browser Chromium.

## Degradation
Without Agent Reach or Chromium, core functions (memory, ledger, ROI gate) still work; scout/browser degrade gracefully with explicit issues (R7.3, R7.2).
