#!/usr/bin/env node
import { scan } from './engine/scanner.js';
import { writeSecurityReport } from './engine/reporter.js';
import { applyFixes, formatFixSummary } from './engine/fixer.js';
import { formatOutput } from './engine/output.js';
import {
  readBaseline,
  writeBaseline,
  diffAgainstBaseline,
} from './engine/baseline.js';
import { loadConfig } from './engine/config.js';
import path from 'node:path';
import fs from 'node:fs/promises';

interface CliArgs {
  cmd: string;
  target: string;
  format: string;
  output?: string;
  fix: boolean;
  dryRun: boolean;
  baseline?: string;
  updateBaseline: boolean;
  layers?: string[];
  rules?: string[];
  watch: boolean;
  noFail: boolean;
  help: boolean;
}

function parseArgs(argv: readonly string[]): CliArgs {
  const args = argv.slice(2);
  const knownCommands = new Set(['scan', 'list', 'rules', 'init', 'baseline']);
  const hasCommand = knownCommands.has(args[0] ?? '');
  const out: CliArgs = {
    cmd: hasCommand ? args[0] : 'scan',
    target: hasCommand && args[1] && !args[1].startsWith('-') ? args[1] : process.cwd(),
    format: 'markdown',
    fix: false,
    dryRun: false,
    updateBaseline: false,
    watch: false,
    noFail: false,
    help: false,
  };

  for (let i = hasCommand && out.target !== process.cwd() ? 2 : hasCommand ? 1 : 0; i < args.length; i++) {
    const a = args[i];
    const next = args[i + 1];
    switch (a) {
      case '--format':
        out.format = next ?? 'markdown';
        i++;
        break;
      case '--output':
      case '-o':
        out.output = next;
        i++;
        break;
      case '--fix':
        out.fix = true;
        break;
      case '--dry-run':
        out.fix = true;
        out.dryRun = true;
        break;
      case '--baseline':
        out.baseline = next;
        i++;
        break;
      case '--update-baseline':
        out.updateBaseline = true;
        break;
      case '--layers':
        out.layers = (next ?? '').split(',').filter(Boolean);
        i++;
        break;
      case '--rules':
        out.rules = (next ?? '').split(',').filter(Boolean);
        i++;
        break;
      case '--watch':
      case '-w':
        out.watch = true;
        break;
      case '--no-fail':
        out.noFail = true;
        break;
      case '--help':
      case '-h':
        out.help = true;
        break;
      default:
        if (!out.target || out.target === process.cwd()) {
          out.target = a;
        }
    }
  }
  return out;
}

function printHelp(): void {
  console.log(`Vibe Security CLI

Usage:
  vibe-security scan [path] [options]
  vibe-security list
  vibe-security init
  vibe-security baseline update [path]

Scan options:
  --format <markdown|json|sarif|junit|compact>   Output format (default: markdown)
  --output, -o <path>                            Output file path
  --fix                                          Apply auto-fixes
  --dry-run                                      Preview auto-fixes without writing
  --baseline <path>                              Show only new findings vs baseline
  --update-baseline                              Write current findings to baseline
  --layers <f,b,n,d,c,o>                         Scan only these layers
  --rules <FE-001,BE-004>                        Run only these rules
  --watch, -w                                    Re-scan on file changes
  --no-fail                                      Exit 0 even with findings

Examples:
  vibe-security scan . --format sarif --output vibe-security.sarif
  vibe-security scan src/ --fix --dry-run
  vibe-security scan . --baseline .vibe-security-baseline.json
  vibe-security init    # Create .vibe-security.json + slash command files
`);
}

async function cmdInit(rootDir: string): Promise<void> {
  const configPath = path.join(rootDir, '.vibe-security.json');
  const slashCommandPath = path.join(rootDir, '.claude', 'commands', 'securityCheck.md');
  const vscodeSettingsPath = path.join(rootDir, '.vscode', 'settings.json');
  const ghInstructionsPath = path.join(rootDir, '.github', 'instructions', 'security-check.instructions.md');
  const agentSkillPath = path.join(rootDir, '.agents', 'skills', 'vibe-security', 'SKILL.md');
  const cursorRulePath = path.join(rootDir, '.cursor', 'rules', 'security.mdc');

  const config = {
    rules: {
      'OBS-002': { severity: 'low' },
    },
    ignore: ['node_modules', 'dist', '.next', 'coverage'],
    output: { format: 'markdown', path: 'Security.md' },
  };

  await fs.mkdir(path.dirname(configPath), { recursive: true });
  await fs.writeFile(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
  console.log(`✅ ${configPath}`);

  for (const [target, content] of [
    [slashCommandPath, SLASH_COMMAND_CLAUDE],
    [vscodeSettingsPath, VSCODE_SETTINGS],
    [ghInstructionsPath, SLASH_COMMAND_GITHUB],
    [agentSkillPath, AGENT_SKILL_ANTIGRAVITY],
    [cursorRulePath, CURSOR_RULE],
  ] as const) {
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, content, 'utf8');
    console.log(`✅ ${target}`);
  }

  console.log('\n👉 Next:');
  console.log('   • Claude Code: type /securityCheck');
  console.log('   • Antigravity / Gemini: .agents/skills/vibe-security skill activated');
  console.log('   • Cursor: .cursor/rules/security.mdc rule activated');
  console.log('   • VS Code: reload window, MCP server will be picked up automatically');
  console.log('   • CI: add `npx -y vibe-security scan . --format sarif` to your workflow');
}

async function cmdList(): Promise<void> {
  const { getAllRules } = await import('./engine/rules/index.js');
  const rules = getAllRules();
  console.log('Available rules:\n');
  for (const r of rules) {
    console.log(
      `  ${r.id.padEnd(8)} ${r.severity.toUpperCase().padEnd(10)} ${r.layer.padEnd(14)} ${r.title}`
    );
  }
  console.log(`\nTotal: ${rules.length}`);
}

async function cmdScan(args: CliArgs): Promise<number> {
  const rootDir = path.resolve(args.target);

  if (args.watch) {
    return cmdWatch(args);
  }

  console.log(` Scanning ${rootDir}...`);
  const config = await loadConfig(rootDir);
  const result = await scan({
    rootDir,
    layers: args.layers as any,
    ruleIds: args.rules,
    ignore: config.ignore,
  });
const baselinePath = args.baseline ?? config.baseline;
  let displayFindings = result.findings;
  if (baselinePath) {
    const baseline = await readBaseline(baselinePath);
    const diff = diffAgainstBaseline(result, baseline);
    displayFindings = diff.newFindings;
    console.log(
      `📋 Baseline: ${baseline ? `${baseline.findings.length} known` : 'none'} -> ${diff.newFindings.length} new, ${diff.resolvedFindings.length} resolved`
    );
  }
if (args.fix) {
    const fixSummary = await applyFixes(result, {
      dryRun: args.dryRun,
      onlyRuleIds: args.rules,
    });
    console.log('\n' + formatFixSummary(fixSummary, args.dryRun));
    if (!args.dryRun && fixSummary.applied.length > 0) {
      console.log(`\n🔧 ${fixSummary.applied.length} file(s) modified.`);
    }
  }
if (args.format === 'markdown') {
    const reportPath = args.output ?? path.join(rootDir, 'Security.md');
    const filtered = { ...result, findings: displayFindings };
    await writeSecurityReport(filtered, reportPath);
    console.log(`📝 Report: ${reportPath}`);
  } else {
    const out = formatOutput(args.format, { ...result, findings: displayFindings });
    const outPath = args.output ?? defaultOutputPath(rootDir, args.format);
    await fs.writeFile(outPath, out, 'utf8');
    console.log(`📝 ${args.format.toUpperCase()} -> ${outPath}`);
  }
if (args.updateBaseline) {
    const basePath = baselinePath ?? path.join(rootDir, '.vibe-security-baseline.json');
    await writeBaseline(basePath, result);
    console.log(`📌 Baseline updated: ${basePath}`);
  }
const sevEmoji: Record<string, string> = {
    critical: '🟣',
    high: '🔴',
    medium: '🟠',
    low: '🟡',
    info: '🔵',
  };
  console.log(
    `\n${displayFindings.length} finding(s) -- ` +
      Object.entries(result.summary.bySeverity)
        .filter(([, n]) => n > 0)
        .map(([s, n]) => `${sevEmoji[s]} ${s}:${n}`)
        .join(' - ')
  );

  return args.noFail || displayFindings.length === 0 ? 0 : 1;
}

function defaultOutputPath(rootDir: string, format: string): string {
  const ext = format === 'sarif' ? 'sarif' : format === 'json' ? 'json' : format === 'junit' ? 'xml' : 'md';
  return path.join(rootDir, `vibe-security.${ext}`);
}

async function cmdWatch(args: CliArgs): Promise<number> {
  const rootDir = path.resolve(args.target);
  console.log(`👀 Watching ${rootDir} (Ctrl+C to stop)...`);

  let running = false;
  async function rescan() {
    if (running) return;
    running = true;
    try {
      const result = await scan({ rootDir });
      const reportPath = path.join(rootDir, 'Security.md');
      await writeSecurityReport(result, reportPath);
      const ts = new Date().toLocaleTimeString();
      console.log(`[${ts}] ${result.summary.totalFindings} finding(s) -> ${reportPath}`);
    } finally {
      running = false;
    }
  }

  await rescan();
console.log('   (3s polling interval)');
  const interval = setInterval(rescan, 3000);
  process.on('SIGINT', () => {
    clearInterval(interval);
    process.exit(0);
  });
  return new Promise(() => {});
}

async function cmdBaseline(args: CliArgs): Promise<number> {
  const sub = args.target; // second positional
  const rootDir = process.cwd();
  if (sub === 'update') {
    const result = await scan({ rootDir });
    const basePath = path.join(rootDir, '.vibe-security-baseline.json');
    await writeBaseline(basePath, result);
    console.log(`📌 Baseline updated: ${basePath} (${result.findings.length} entries)`);
    return 0;
  }
  console.error('Usage: vibe-security baseline update');
  return 2;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv);

  if (args.help || args.cmd === '--help' || args.cmd === '-h') {
    printHelp();
    return 0;
  }

  if (args.cmd === 'list' || args.cmd === 'rules') return cmdList().then(() => 0);
  if (args.cmd === 'init') return cmdInit(args.target).then(() => 0);
  if (args.cmd === 'baseline') return cmdBaseline(args);
  if (args.cmd === 'scan' || args.cmd === undefined) return cmdScan(args);

  console.error(`Unknown command: ${args.cmd}`);
  printHelp();
  return 2;
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
const SLASH_COMMAND_CLAUDE = `---
description: Run Vibe Security scan on the current project and report findings
---

Scan this project for security issues.

Use the following MCP tools in order:

1. **mcp__vibe-security__scan_project** -- Scan the entire project. Set the \`rootDir\` parameter to the current working directory.

2. If the user provided arguments (\$ARGUMENTS):
   - \`--frontend\` / \`--backend\` / \`--network\` / \`--database\` / \`--cicd\` / \`--observability\` -> filter via the \`layers\` parameter
   - \`--fix\` -> call \`mcp__vibe-security__get_rule_detail\` for the top 3 critical rules to extract fix suggestions, then present an apply plan to the user
   - \`--baseline\` -> compare \`mcp__vibe-security__scan_project\` output against the existing baseline, report only the new findings
   - \`--rule <id>\` -> run only that rule (\`ruleIds\` parameter)
   - \`--json\` -> request JSON output instead of the table format

3. Summarize findings in order: **critical -> high -> medium -> low**.

4. For the **first 3 findings**, write concrete fix suggestions (with code examples).

5. \`Security.md\` is already written by the MCP server. Show the user the file path and total finding count.

Do NOT:
- Hide or downplay findings.
- Suggest a fix you are not sure about; point the user to the rule documentation instead.
- Ask clarifying questions before scanning -- scan directly.
`;

const VSCODE_SETTINGS = JSON.stringify(
  {
    'mcp.servers': {
      'vibe-security': {
        command: 'vibe-security',
        type: 'stdio',
      },
    },
  },
  null,
  2
) + '\n';

const SLASH_COMMAND_GITHUB = `---
description: Auto-invoked when user runs /securityCheck -- runs Vibe Security MCP scan and explains findings
applyTo: "**"
---

When the user runs /securityCheck (with or without arguments), you MUST:

1. Call the MCP tool \`scan_project\` provided by the \`vibe-security\` server.
   - \`rootDir\`: \${workspaceFolder}
   - If the user passed --frontend, --backend, --network, --database, --cicd, or --observability, pass the matching \`layers\` filter.
   - If the user passed --fix, also call \`get_rule_detail\` for the top 3 critical findings and present auto-fix suggestions inline.
   - If the user passed --rule <id>, pass \`ruleIds: [<id>]\`.
2. Summarize the result as a table: severity, count, top 3 files.
3. For each Critical and High finding, show: file:line, snippet, one-line fix.
4. Confirm that Security.md was written at the workspace root.
5. If no findings: congratulate the user.

Do not ask clarifying questions before scanning -- just scan.

Available MCP tools:
- \`scan_project\` -- full project scan
- \`scan_file\` -- single file scan
- \`list_rules\` -- list all rules
- \`get_rule_detail\` -- get rule details (use this for auto-fix suggestions)
- \`apply_fix\` -- preview or apply auto-fixes
`;

const AGENT_SKILL_ANTIGRAVITY = `---
name: vibe-security
description: Security guard and automated remediation skill for AI-generated code. Scans projects across frontend, backend, database, network, cicd, and observability layers, detects vulnerabilities, and safely plans and applies auto-fixes.
---

# Vibe Security - Agent Action Protocol (AAP) Skill

When performing security checks or auditing generated code, use the Vibe Security tools:
1. Scan project via MCP \`scan_project\` or CLI \`vibe-security scan .\`.
2. Inspect Critical and High findings.
3. For auto-fixable findings, use MCP \`apply_fix\` with \`dryRun: true\` to inspect diffs, then apply with \`dryRun: false\`.
4. Check \`Security.md\` for complete remediation instructions.
`;

const CURSOR_RULE = `---
description: Run security checks and remediation on project code
globs: *
alwaysApply: false
---

# Vibe Security Guard

- Before committing or completing feature implementation, run \`vibe-security scan .\`.
- Review critical findings in \`Security.md\`.
- Use \`vibe-security scan . --fix --dry-run\` to preview automatic patches for common security vulnerabilities (XSS, cookie flags, security headers).
`;
