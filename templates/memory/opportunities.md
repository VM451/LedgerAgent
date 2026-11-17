# Opportunities — Live Market Scans

Updated: {{ts}}
Source: Agent Reach (untrusted read-only intelligence)

## Scoring
For each lead: effective_hourly_usd = (expected_gross_usd - cost_basis_usd) / estimated_hours
roi_multiple = expected_gross_usd / cost_basis_usd
- Reject if effective_hourly_usd < profile.min_hourly_yield_usd (e.g., $0.42/hr grind)
- Reject if roi_multiple < 2.0
- Require evidence_url from scout_search/read

## Leads
| ts | channel | title | url | expected_gross | cost_basis | hours | $/hr | roi | verdict |
|----|---------|-------|-----|---------------|------------|-------|------|-----|---------|
| _empty — scout via Agent Reach_ | | | | | | | | | |

## Rejected (low-yield grind)
- $10 / 24h = $0.42/hr < $5.00 hurdle → auto-rejected
