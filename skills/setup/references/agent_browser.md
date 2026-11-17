# Agent Browser Hands

- Use `snapshot -i` for accessibility tree with @eN refs.
- Always pass --session <name> persisted under `${PLUGIN_DATA}/browser-profiles/`.
- Never attach to user's personal Chrome; isolated profiles only.
- Domain proxy enforces allowed_domains[] on open and redirects.
- On CAPTCHA/2FA/expired cookie, call browser_auth_handoff and log trigger.
