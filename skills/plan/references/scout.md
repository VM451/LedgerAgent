# Scout (Agent Reach) — Untrusted Sensing

- Scout_* tools wrap `agent-reach` CLI read-only.
- All outputs marked untrusted:true, never auto-execute.
- Channels: github, v2ex, youtube, bilibili, web (default); reddit, xiaohongshu, linkedin, boss, xueqiu, x (optional).
- Always persist raw leads + rejected low-ROI to opportunities.md.
- Ordered fallbacks: bili-cli, yt-dlp, Jina Reader, Exa, OpenCLI.
