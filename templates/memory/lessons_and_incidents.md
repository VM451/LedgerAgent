# Lessons & Incidents

Updated: {{ts}}

## Portal Playbooks
- (selector quirks, API quirks, CAPTCHA triggers)

## Incidents
| ts | incident | root_cause | remediation | handoff |
|----|----------|------------|-------------|---------|
| _empty_ | | | | |

## Known Failure Modes
- CAPTCHA/2FA → browser_auth_handoff, log trigger
- Expired cookie → refresh via setup skill
- Orphaned browser daemon → wallet_recover reaps
