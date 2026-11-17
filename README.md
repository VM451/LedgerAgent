# LedgerAgent

**Self-directed autonomous earning agent with open-ended discovery, unit-economics gating, persistent memory, and a 5-stage lifecycle — delivered as a portable Agent Plugin.**

Give it a budget and a guardrail envelope; it scouts the real internet, rejects low-pay grind, designs its own high-ROI plan, executes autonomously across web and code, remembers everything across sessions, and pays out to your account.

![Rust](https://img.shields.io/badge/rust-ledger--mcp-682c2e?style=flat-square) ![MCP](https://img.shields.io/badge/mcp-2026--07--28-0ea5e9?style=flat-square) ![Skills](https://img.shields.io/badge/skills-5--lifecycle-7c3aed?style=flat-square) ![Agent-Reach](https://img.shields.io/badge/eyes-agent--reach-0f766e?style=flat-square) ![Agent-Browser](https://img.shields.io/badge/hands-agent--browser-6a5cff?style=flat-square)

---

## What it is

Traditional “AI money-making” setups fail because they require spoon-feeding or trap the agent in brittle templates. LedgerAgent solves six gaps:

1. **Hardcoded Menu Trap** — static catalogs go stale; agent authors its own plans from live signals while Rust enforces caps.
2. **Opportunity Cost Blindness ($10/24h vs $100/24h)** — every plan passes `effective_hourly_usd` + `roi_multiple` + prerequisite gate before proposal.
3. **Cross-Session Amnesia** — `AGENTS.md` + 5 Markdown memory files in `${PLUGIN_DATA}/memory/` restore context cold-start in one turn.
4. **No Eyes/Hands** — Agent Reach senses demand; Agent Browser executes via `snapshot -i @eN` under domain allowlists.
5. **Micromanagement vs Unbounded Risk** — one approved envelope (`max_task_usd`, `max_day_usd`, `allowed_domains[]`, `min_hourly_yield_usd`).
6. **Unrecoverable Failures** — CAPTCHAs/expired cookies/stuck daemons halt cleanly and recover via `wallet_verify`/`wallet_recover`.

**Server is the gate; the skill is the pitch.** Skills teach reasoning; Rust enforces caps, domains, ROI floors, path containment, and secret redaction.

## Quickstart

```bash
# 1. Clone
git clone https://github.com/VM451/LedgerAgent.git && cd LedgerAgent

# 2. Build (Rust 1.99+)
cargo build --release
./bin/ledger-mcp doctor

# 3. Wire memory (idempotent AGENTS.md injection)
# via MCP: setup_init_memory { workspace_dir: "." }
# or manually:
./bin/ledger-mcp install --print --format=agents-md >> AGENTS.md

# 4. Install eyes & hands
agent-reach setup && agent-reach doctor --text
npm i -g agent-browser && agent-browser install

# 5. Register MCP (any client)
./bin/ledger-mcp install --print --target=claude-code
```

-> [INSTALL.md](./INSTALL.md) for manual install on any Skills+MCP client (T3 first-class).

## Lifecycle — 5 skills

```
AGENTS.md + memory/*.md (5 files)  <->  CRUD  <->  setup / plan / run / wallet / deposit
```

| # | Skill | Memory files | Purpose |
|---|-------|--------------|---------|
| 1 | `setup` | `profile.md` | Day-0 onboarding, ROI hurdles, broker/keychain, Agent Reach/Browser verification |
| 2 | `plan` | `opportunities.md`, `lessons_and_incidents.md` | Wild scouting via Agent Reach, ROI filter, self-authored `plan_propose` |
| 3 | `run` | `active_plan.md`, `execution_log.md` | Autonomous loop, `snapshot -i @eN`, yield-drift watchdog, HITL escalations |
| 4 | `wallet` | `execution_log.md`, `lessons_and_incidents.md` | Treasury, hash-chain audit, `wallet_halt`, recovery, CSV export |
| 5 | `deposit` | `profile.md`, `execution_log.md` | Whitelisting, quotes, idempotent payouts, reversal recovery |

Each `SKILL.md` is ≤10k lines, edge runbooks in `references/` one level deep.

## Architecture

```
                ┌───────────────── Rust core (ledger-mcp) ────────────────┐
     MCP stdio  │  Policy + Signer   Ledger (SQLite WAL hash chain)      │
 ┌─────────────►│  Unit-Economics    Memory (allowlist + scrub)          │
 │              │  Gate (ROI)        Scout* (Agent Reach)  Browser*       │
 │              │  State Machine     Doctor / install --print             │
 │              └────────────────────────────────────────────────────────┘
 │                ${PLUGIN_DATA}/memory/  state.db  browser-profiles/
 │                ${PLUGIN_DATA}/broker.sock (0600)  vault.db
 └─ Agent (Claude Code / Qwen / Codex / any Skills+MCP harness)
```

- **R8.1** `./bin/ledger-mcp` — one token, `stdio`, no `npx`.
- **R8.2** Only `${PLUGIN_ROOT}` / `${PLUGIN_DATA}` expand (args/env/cwd).
- **R8.3** All mutable state in `${PLUGIN_DATA}`; `PLUGIN_ROOT` read-only; Agent Reach isolated in `~/.agent-reach/`.
- **R13.6** `#![deny(unsafe_code)]` outside alloy/keyring.
- **R12.11 / R15** Secret scrubber redacts keys/mnemonics/scripts before any `memory_write`.

Full spec: [PRD-001](./docs/PRD.md) if present, [INSTALL.md](./INSTALL.md), `spec/tools/*.json`.

## Tools (MCP)

```jsonc
// setup / health
setup_doctor, setup_init_memory

// persistent memory (allowlisted, scrubbed, auto-rotate >24K → archive/YYYY-MM.md)
memory_read, memory_write, memory_append, memory_delete

// eyes — Agent Reach (untrusted:true, read-only)
scout_channels, scout_search, scout_read

// hands — Agent Browser (allowlisted via approved plan, snapshot -i @eN)
browser_open, browser_snapshot, browser_act, browser_close, browser_auth_handoff

// plan gate (Rust ROI)
plan_propose, plan_edit, plan_approve

// run loop (refuses without approved unexpired plan)
run_execute, run_status, run_halt, run_resume

// treasury
wallet_init, wallet_status, wallet_history, wallet_breakdown, wallet_verify, wallet_recover, wallet_halt

// payout (confirmed destinations only)
deposit_destinations, deposit_add, deposit_quote, deposit_execute, deposit_status

// credentials (no secrets returned)
credentials_status, credentials_begin
```

Key gates:
- `effective_hourly_usd = (expected_gross_usd - cost_basis_usd) / estimated_hours >= min_hourly_yield_usd`
- `roi_multiple = expected_gross_usd / cost_basis_usd >= 2.0`
- `prerequisites[] all ready == true` and `evidence_urls[] >=1` from live `scout_*`
- `browser_open` / `run_execute` require `approved` + unexpired plan; `domain_allowed()` checks `allowed_domains[]`
- `wallet_verify` checks `prev_hash -> hash`; drift >0.5% halts

CLI:
```bash
./bin/ledger-mcp doctor                          # containment, chain, memory, Reach/Browser
./bin/ledger-mcp setup_doctor                    # JSON health
./bin/ledger-mcp install --print --target=<name> # MCP config block
./bin/ledger-mcp install --print --format=skills # destination path
./bin/ledger-mcp install --print --format=agents-md # idempotent AGENTS.md block
```

## Persistent Memory

`${PLUGIN_DATA}/memory/` (default `~/.ledger-agent/memory/`):

| File | Content |
|------|---------|
| `profile.md` | ROI hurdles, caps, payout corridor, banned niches |
| `opportunities.md` | Live scans, unit-economics scores, rejected grind |
| `active_plan.md` | Approved envelope, `allowed_domains[]`, checkpoint |
| `execution_log.md` | Journal of tasks, realized $/hr, net yield |
| `lessons_and_incidents.md` | Portal quirks, CAPTCHA triggers, fixes |

`setup_init_memory`:
- Creates `AGENTS.md` when absent with `<!-- LedgerAgent:memory:start -->` protocol block.
- Preserves 100% of user content; only updates fenced block when exists.
- Wires `@AGENTS.md` into `CLAUDE.md`/`GEMINI.md` when present.
- Each file capped 32 KB; `opportunities.md`/`execution_log.md` >24 KB rotate to `archive/YYYY-MM.md`.

Cold-start: `memory_read all` → `active_plan.md` + `profile.md` restore in one turn (G6).

## Harness Support (R7)

| Tier | Harness | Mechanism |
|------|---------|-----------|
| T1 | Claude Code, Qwen Code, Codex CLI, Antigravity | `.claude-plugin/`, `gemini-extension.json`, `.codex/config.toml`, CI matrix |
| T2 | Kimi Code, Muse Code, Step Code, etc. | `.kimi-plugin/` + Claude shim reuse |
| T3 | Mirror, any other client | Manual via `INSTALL.md` + `--print` (no shim) |

Portable core works with **zero shim files** and degrades if optional Reach channels/Chromium missing (R7.3).

## Security & Compliance

- `0600` broker socket, OS keychain refresh tokens, AES-256-GCM `vault.db` (R12).
- Agent Reach: read-only, `untrusted:true`; Browser: isolated `${PLUGIN_DATA}/browser-profiles/`, no personal Chrome, allowlist on open + redirects, downloads disabled.
- Secret scrubber (regex + entropy) on every memory write; block `<script>` payloads.
- ToS: Reach view-only; Browser only on user-approved domains, no CAPTCHA bypass/spam — escalates via `browser_auth_handoff` (R17, `docs/tos/`).

See `docs/tos/README.md` for per-provider review (launch blocker if automation banned).

## Repo Layout

```
├── plugin.json / mcp.json        # portable Agent Plugin spec (10-field closed schema)
├── .muse-plugin/plugin.json      # Muse native manifest (skills + mcpServers)
├── INSTALL.md / CHANGELOG.md / LICENSE
├── bin/ledger-mcp*               # launcher + 5 platform binaries
├── skills/{setup,plan,run,wallet,deposit}/SKILL.md (+ references/)
├── templates/AGENTS.ledger.md + memory/{5}.md
├── src/main.rs                   # Rust MCP server, ledger, gates, bridges
├── spec/tools/*.json             # schemars-generated, CI-diffed
├── .claude-plugin/ .codex/ .kimi-plugin/ gemini-extension.json com.ledger/
└── docs/tos/
```

## Development

```bash
cargo test                 # unit: ROI grind vs leverage, domain allowlist, scrub, allowlist
cargo test -- --nocapture  # see ledger chain checks
./bin/ledger-mcp doctor
PLUGIN_DATA=/tmp/t ./bin/ledger-mcp doctor
```

**Tests cover acceptance criteria:**
- `$10/24h` auto-rejected, `$100/10h` accepted
- No secrets in shipped files (scrubber)
- `AGENTS.md` idempotent, user content preserved
- Browser blocked without approved plan / outside `allowed_domains[]`
- Over-cap requests rejected
- Chain verified on start + `wallet_verify`; break → `wallet_recover`

## Non-goals (v1)

Fiat on-ramp, multi-user, tax filing (CSV only), mobile app, hardcoded strategy templates, custodial fiat, spam/CAPTCHA cracking, guaranteed profit.

## License

Proprietary — see [LICENSE](./LICENSE).

## Contributing

PRs to `main` only. Keep atomic per-file commits (Conventional Commits, 1–3 files), `cargo test` green, `muse skills validate` + `muse plugins validate` clean.

## Links

- [Agent Reach](https://github.com/Panniantong/Agent-Reach) (eyes)
- [Agent Browser](https://github.com/vercel-labs/agent-browser) (hands)
- [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
