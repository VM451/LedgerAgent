---
name: setup
description: Initialize and diagnose the LedgerAgent environment — connect credential broker, create ERC-4337 smart account, bootstrap AGENTS.md and the 5 persistent memory markdown files with user ROI hurdles, configure Agent Reach internet channels, verify Agent Browser headless runtime, and refresh expired web sessions. Use on first run, when doctor reports issues, or when a channel/browser session needs human login.
license: Proprietary
metadata:
  contract: ledger.setup.v1
---

# Setup

## 0. System Diagnostics
Call `setup_doctor`. Inspect status across five subsystems:
1. **Broker & Keychain:** Unix socket `0600` + OS keyring availability.
2. **Smart Account:** ERC-4337 task wallet + separate send-only payout address.
3. **Persistent Memory (`AGENTS.md` + `memory/`):** Workspace `AGENTS.md` memory hook + 5 Markdown files in `${PLUGIN_DATA}/memory/`.
4. **Eyes (`Agent Reach`):** Installed channels (`github`, `youtube`, `bilibili`, `v2ex`, `web`, and optional `x`, `reddit`, `xiaohongshu`, `linkedin`, `boss`, `xueqiu`).
5. **Hands (`Agent Browser`):** Binary version + headless Chromium readiness.

## 1. Bootstrap Persistent Memory & Autonomy Preferences
- Call `setup_init_memory` to create `${PLUGIN_DATA}/memory/*.md` and wire `AGENTS.md`.
- Establish the user's high-level operating preferences once (and store in `profile.md` via `memory_write`):
  - **Minimum Effective Hourly Yield (`min_hourly_yield_usd`):** Default `$5.00/hr` (e.g., rejects `$10/24h` grind, accepts `$100/24h` opportunities).
  - **Max Daily Risk Budget (`max_day_usd`):** Default `$5.00/day`.
  - **Capabilities & Constraints:** Available compute/tools, banned niches, and preferred payout corridor.

## 2. Credential Broker & Wallet Init
- If `credentials_status` shows `missing[]`, run `credentials_begin` and give the user the device/PKCE URL and code. Wait until verified.
- If no smart account exists, call `wallet_init` and present the task wallet address (for external funding) and the separate payout address.

## 3. Configure Eyes & Hands
- Enable default Agent Reach channels (`github`, `youtube`, `bilibili`, `v2ex`, `web`) and any optional channels requested by the user inside isolated `~/.agent-reach/`.
- Run `browser_doctor` to confirm isolated `${PLUGIN_DATA}/browser-profiles/` readiness. If a platform requires initial login (2FA/OAuth), launch an interactive HITL window via `browser_auth_handoff`.

## 4. Readiness Gate
Re-run `setup_doctor`. Once green, immediately offer to launch `plan` so the agent can go scout the internet on its own.

## Rules
- Never overwrite user-authored sections of an existing `AGENTS.md`; only manage the fenced `LedgerAgent:memory` block.
- Never ask the user to paste passwords, private keys, or API keys into chat, and never write secrets into `memory/*.md`.
- Always recommend secondary/work accounts for Agent Reach social channels.
