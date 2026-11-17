# Yield Drift Watchdog

- Every 5 tasks or 6 hours: realized = net_revenue / elapsed_hours.
- If realized < 0.5 * min_hourly_yield_usd, pause and propose pivot via plan.
- Append realized $/hr to execution_log.md on every check.
- 3 consecutive failures → run_halt.
