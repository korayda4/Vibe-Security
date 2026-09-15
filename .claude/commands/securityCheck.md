---
description: Run Vibe Security scan on the current project and report findings
---

Scan this project for security issues.

Use the following MCP tools in order:

1. **`mcp__vibe-security__scan_project`** — Scan the entire project. Set the `rootDir` parameter to the current working directory.

2. If the user provided arguments (`$ARGUMENTS`):
   - `--frontend` / `--backend` / `--network` / `--database` / `--cicd` / `--observability` → filter via the `layers` parameter
   - `--fix` → call `mcp__vibe-security__get_rule_detail` for the top 3 critical rules to extract fix suggestions, then present an apply plan to the user
   - `--baseline` → compare `mcp__vibe-security__scan_project` output against the existing baseline, report only the new findings
   - `--rule <id>` → run only that rule (`ruleIds` parameter)
   - `--json` → request JSON output instead of the table format

3. Summarize findings in order: **critical → high → medium → low**.

4. For the **first 3 findings**, write concrete fix suggestions (with code examples).

5. `Security.md` is already written by the MCP server. Show the user the file path and total finding count.

Do NOT:
- Hide or downplay findings.
- Suggest a fix you are not sure about; point the user to the rule documentation instead.
- Ask clarifying questions before scanning — scan directly.
