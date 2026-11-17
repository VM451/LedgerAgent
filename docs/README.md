# Docs

## Structure

| File | Purpose |
|------|---------|
| [../README.md](../README.md) | Product overview, quickstart, architecture |
| [../INSTALL.md](../INSTALL.md) | Manual install on any client (T3, 5 sections) |
| [tos/README.md](./tos/README.md) | Per-provider ToS review (R17.3 launch blocker) |

## Architecture Notes

- **Core:** `src/main.rs` — stdio MCP, SQLite WAL ledger (`*_chain`), `Policy` gate, `memory_*` allowlist.
- **Sensing:** `scout_*` wraps `agent-reach` CLI fallback chain (bili-cli → yt-dlp → Jina → Exa → OpenCLI), `untrusted:true`.
- **Hands:** `browser_*` wraps `agent-browser` CLI (`snapshot -i` + `@eN`), `allowed_domains[]` enforced in Rust on `browser_open` and redirects, isolated `${PLUGIN_DATA}/browser-profiles/`.
- **Memory:** `${PLUGIN_DATA}/memory/*.md` allowlist + scrubber + 24K rotation; `AGENTS.md` fenced `<!-- LedgerAgent:memory:start/end -->`.
- **Wallets:** ERC-4337 task wallet + send-only payout; `wallet_verify`/`wallet_recover` recompute `SHA256(seq|ts|kind|...|prev_hash)`.

## Harness Tiers (R7)

- **T1** (CI-gated): Claude Code, Qwen Code, Codex CLI, Antigravity — shims in `.claude-plugin/`, `gemini-extension.json`, `.codex/`
- **T2** (smoke-tested): Kimi Code, Muse Code, etc. — `.kimi-plugin/` + Claude shim reuse
- **T3** (manual): Mirror / any other — `INSTALL.md` + `ledger-mcp install --print`

All tiers degrade if optional Reach channels/Chromium unavailable — core (memory/ledger/ROI gate) remains functional.

## Tool Contracts

Full JSON schemas in `../spec/tools/*.json` (schemars-generated). Key invariants:

- `plan_propose` rejects if `effective_hourly_usd < min_hourly_yield_usd` or `roi_multiple < 2.0` or missing `evidence_urls[]` or unready `prerequisites[]`
- `run_execute` / `browser_*` refuse without approved unexpired plan (R11.1)
- `deposit_quote`/`deposit_execute` require confirmed destination (read-back)

## Operational Runbooks

See skills `references/`:

- `setup/references/broker.md` — broker socket perms, vault
- `setup/references/agent_browser.md` — session isolation, allowlist
- `plan/references/scout.md` — untrusted sensing
- `run/references/yield.md` — drift watchdog
- `wallet/references/recovery.md` — incident recovery
- `deposit/references/corridors.md` — Rain/Gnosis/Bridge/BVNK

## Compliance (R17)

- Reach: read-only viewing only
- Browser: approved domains only, respects target ToS, no CAPTCHA bypass (HITL)
- Record per-provider ToS review in `tos/`; automation bans block launch
