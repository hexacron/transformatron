# transformatron

**Read [AGENTS.md](AGENTS.md).** It is the canonical agent guide for this repository and applies
to Claude Code exactly as written — the loop, the verification gates, and the constraints all
hold. This file exists only because Claude Code loads `CLAUDE.md` by convention; keeping the
guidance in one file stops the two from drifting apart.

Two Claude-specific notes:

- The `transformatron` MCP server is registered in `.mcp.json` and gives you the tools listed in
  AGENTS.md (`scaffold_transform`, `server_restart`, `run_transform`, and so on). Prefer them over
  the CLI when they are available; they call the same code.
- Approval for that MCP server is recorded per-machine in `.claude/settings.local.json`, which is
  gitignored, so a fresh clone prompts again. If the tools are unavailable, the CLI in
  `scripts/transformatron_cli.py` does everything they do.

Before writing or editing a transform, read `docs/transform-authoring.md` — it corrects the SDK
guidance where it is wrong and describes the scaffold, run and read loop.
