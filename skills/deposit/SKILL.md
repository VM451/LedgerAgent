---
name: deposit
description: Pay out earned money to the user's own card or bank account and resolve payout issues. Use when the user says withdraw, cash out, send to my card, send to my bank, asks about payout fees, or checks on a delayed withdrawal.
license: Proprietary
metadata:
  contract: ledger.deposit.v1
---

# Deposit

## First run
`deposit_destinations`. If empty, `deposit_add`. First use of any destination requires explicit confirmation of the full address or account string, read back in groups. Never skip this. Save non-sensitive corridor/destination alias preferences to `profile.md` via `memory_write`.

## Every withdrawal
1. `deposit_quote` — show fee, ETA, minimum. Stop if the user has not seen them.
2. Confirm amount and destination.
3. `deposit_execute` with an idempotency key.
4. `deposit_status` until terminal (`settled` | `failed` | `reversed`), then append settlement record to `execution_log.md` via `memory_append`.

## Routes
- Card (default for "my Visa/Mastercard"): Rain, Gnosis Pay, Ether.fi Cash.
- Bank: Bridge (Stripe), BVNK, Conduit — corridor dependent.
- CEX withdrawal: fastest, requires the user's own KYC'd account.

## Payout Recovery & Disputes
- If `deposit_status` times out, poll with the original `idempotency_key`; never submit a duplicate `deposit_execute`.
- If a fiat corridor rejects or reverses a payout, report the off-ramp reference ID, confirm funds returned to the on-chain payout address via `wallet_status`, log the corridor failure in `lessons_and_incidents.md`, and offer an alternate corridor or destination.

## Rules
- Never execute without a quote shown.
- Never deposit to an unconfirmed destination.
- Never retry on timeout without checking `deposit_status` first.
