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
  targetPath?: string;
  detailed: boolean;
  lint: boolean;
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
    detailed: false,
    lint: false,
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
      case '--detailed':
      case '-d':
        out.detailed = true;
        break;
      case '--lint':
        out.lint = true;
        out.layers = out.layers ? [...out.layers, 'lint'] : ['lint'];
        break;
      case '--dir':
      case '--path':
        out.targetPath = next;
        i++;
        break;
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
  --dir, --path <path>                           Target specific directory or file (relative to root)
  --detailed, -d                                 Run comprehensive deep scan with elevated limits
  --lint                                         Include or focus on language quality and syntax lint rules
  --format <markdown|json|sarif|junit|compact>   Output format (default: markdown)
  --output, -o <path>                            Output file path
  --fix                                          Apply auto-fixes
  --dry-run                                      Preview auto-fixes without writing
  --baseline <path>                              Show only new findings vs baseline
  --update-baseline                              Write current findings to baseline
  --layers <f,b,n,d,c,o,lint>                    Scan only these layers
  --rules <FE-001,BE-004,LINT-001>               Run only these rules
  --watch, -w                                    Re-scan on file changes
  --no-fail                                      Exit 0 even with findings

Examples:
  vibe-security scan . --detailed
  vibe-security scan src/api/ --format sarif
  vibe-security scan src/ --fix --dry-run
  vibe-security scan . --baseline .vibe-security-baseline.json
  vibe-security init    # Create .vibe-security.json, slash commands, and Agent Skill files
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
  console.log('   • Claude Code: type /securityCheck [path] [--detailed]');
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
  const resolvedTarget = path.resolve(args.target);
  let rootDir = process.cwd();
  let targetPath = args.targetPath;

  // Check if args.target is a subdirectory or specific file inside cwd
  if (resolvedTarget !== rootDir && !targetPath) {
    if (resolvedTarget.startsWith(rootDir + path.sep)) {
      targetPath = path.relative(rootDir, resolvedTarget);
    } else {
      rootDir = resolvedTarget;
    }
  }

  if (args.watch) {
    return cmdWatch(args);
  }

  const scopeMsg = targetPath ? `${rootDir} (target: ${targetPath})` : rootDir;
  const modeMsg = args.detailed ? ' [Detailed Deep Scan]' : '';
  console.log(`🔍 Scanning ${scopeMsg}...${modeMsg}`);

  const config = await loadConfig(rootDir);
  const result = await scan({
    rootDir,
    targetPath,
    detailed: args.detailed,
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
description: Run Vibe Security scan on project or specific directory with security and lint checks
---

Scan this project for security vulnerabilities and language/lint quality issues.

Use the following MCP tools:

1. **scan_project** -- Call \`scan_project\` with \`rootDir\` set to the workspace root.
   - If user provided a path or directory argument (e.g. \`src/api\`, \`frontend\`, or \`--dir <path>\`): pass it as \`targetPath\`.
   - If user passed \`--detailed\` or asked for in-depth/detailed check: pass \`detailed: true\`.
   - If user passed \`--frontend\` / \`--backend\` / \`--lint\` / \`--network\` / \`--database\`: filter via \`layers\`.
   - If user passed \`--rule <id>\`: pass \`ruleIds: [<id>]\`.
   - If user passed \`--fix\`: run \`apply_fix\` with \`dryRun: true\` to preview diffs before applying.

2. Summarize findings clearly into two distinct sections:
   - **🛡️ Security Findings** (Critical, High, Medium, Low)
   - **🧹 Language & Lint Quality Issues** (Unhandled exceptions, floating promises, type bypasses, syntax errors)

3. For top critical findings, show: \`file:line\`, snippet, and clear one-line fix.
4. Report the location of \`Security.md\`.
`;

const VSCODE_SETTINGS = JSON.stringify(
  {
    'mcp.servers': {
      'vibe-security': {
        command: 'vibe-security-mcp',
        type: 'stdio',
      },
    },
  },
  null,
  2
) + '\n';

const SLASH_COMMAND_GITHUB = `---
description: Auto-invoked when user runs /securityCheck -- runs Vibe Security scan with security and lint checks
applyTo: "**"
---

When the user runs /securityCheck (with or without arguments):

1. Call the MCP tool \`scan_project\`:
   - \`rootDir\`: \${workspaceFolder}
   - If user provided a path argument or \`--dir <path>\`: pass \`targetPath: "<path>"\`.
   - If user passed \`--detailed\`: pass \`detailed: true\`.
   - If user passed \`--frontend\`, \`--backend\`, \`--lint\`, \`--network\`, \`--database\`: pass matching \`layers\`.
   - If user passed \`--fix\`: call \`apply_fix\` with \`dryRun: true\` to preview patches.
2. Group and display findings:
   - 🛡️ Security Vulnerabilities
   - 🧹 Language & Lint Quality Issues
3. For each finding, list \`file:line\`, brief description, and actionable remediation.
4. Confirm that \`Security.md\` was generated at the workspace root.
`;

const AGENT_SKILL_ANTIGRAVITY = `---
name: vibe-security
description: Security guard, lint checker, and automated remediation skill for AI-generated code. Scans projects across frontend, backend, database, network, cicd, observability, and lint layers, detects vulnerabilities, and safely applies auto-fixes.
---

# Vibe Security - Agent Action Protocol (AAP) Skill

When performing security audits or code quality reviews:
1. **General Scan:** Call \`scan_project({ rootDir: "." })\`.
2. **Targeted Folder Scan:** Call \`scan_project({ rootDir: ".", targetPath: "path/to/folder" })\`.
3. **Detailed Scan:** Call \`scan_project({ rootDir: ".", detailed: true })\` for deep limits and full context.
4. **Remediation:** For auto-fixable findings, call \`apply_fix({ dryRun: true })\` to review the unified diff, then \`apply_fix({ dryRun: false })\` to apply.
5. Check \`Security.md\` for complete audit documentation.
`;

const CURSOR_RULE = `---
description: Run security checks and remediation on project or specific folders
globs: *
alwaysApply: false
---

# Vibe Security Guard

- Run \`vibe-security scan .\` for general project scan.
- Run \`vibe-security scan <path> --detailed\` for targeted deep directory scans.
- Run \`vibe-security scan . --lint\` to check for language-specific anti-patterns (empty catches, floating promises, type bypasses).
- Use \`vibe-security scan . --fix --dry-run\` to preview automatic patches for common security and lint errors.
`;
