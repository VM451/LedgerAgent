---
name: wallet
description: Manage the agent's money, audit integrity, emergency stop, and failure recovery — check balance, principal vs yield, spend caps, hash-chain verification, emergency halt, stuck transaction/browser daemon recovery, incident memory updates, and tax CSV export. Use when the user asks what it has, what it earned, what it spent, wants an emergency stop, or needs to recover from a halt or error.
license: Proprietary
metadata:
  contract: ledger.wallet.v1
---

# Wallet & Recovery

## 1. Treasury Inspection
1. `wallet_status` always first.
2. `wallet_history` default page only (or `--export` for CSV tax export).
3. `wallet_breakdown` if asked where money went.

## Report Format
- **Available:** USD, then native.
- **Earned:** yield only, never blended into balance.
- **Today:** spend / cap as a fraction.
- `drift > 0.5%` → state it and stop.

## 2. Emergency Halt
`wallet_halt` is a hard stop: revokes active session key signing, kills all in-flight jobs, and terminates active Agent Browser daemons. Confirm first — unless an active security/drift anomaly triggered auto-halt.

## 3. Incident & State Recovery
When the system is halted, drifted, or stuck, execute recovery in order:
1. `wallet_verify` — validate SQLite append-only hash chain (`prev_hash` → `hash`) and reconcile against on-chain ERC-4337 balances.
2. `wallet_recover` — clean up orphaned Agent Browser processes/locks, cancel or replace stuck userOps/nonces, and quarantine corrupted partial task states.
3. Record root cause and remediation in `lessons_and_incidents.md` via `memory_append`, and update `active_plan.md` status so future sessions do not repeat the failure.
4. Present root-cause summary and require explicit user confirmation before calling `run_resume`.
