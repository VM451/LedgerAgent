# Broker & Keychain

- Socket at `${PLUGIN_DATA}/broker.sock`, 0600.
- Refresh tokens in OS keychain; access tokens in memory only.
- Vault at `${PLUGIN_DATA}/vault.db` AES-256-GCM.
- If `credentials_status` missing, run `credentials_begin` (device/PKCE).
- Never expose secrets via MCP.
