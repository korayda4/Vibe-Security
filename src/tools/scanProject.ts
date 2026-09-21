import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { scan } from '../engine/scanner.js';
import { writeSecurityReport } from '../engine/reporter.js';
import type { Finding, Layer, ScanOptions } from '../types.js';

export const scanProjectToolDefinition = {
  name: 'scan_project',
  description:
    'Scan the project for security vulnerabilities and language/lint errors across all layers. Supports full project scans or targeted directory scans, and detailed deep analysis.',
  inputSchema: {
    type: 'object',
    properties: {
      rootDir: {
        type: 'string',
        description: 'Project root directory (default: cwd)',
      },
      targetPath: {
        type: 'string',
        description: 'Target specific directory or file path relative to rootDir (for example: "src/api", "frontend", "server")',
      },
      detailed: {
        type: 'boolean',
        description: 'Run comprehensive deep scan with elevated finding limits and full context (default: false)',
        default: false,
      },
      layers: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability', 'lint'],
        },
        description: 'Limit scan to selected layers (including lint for language quality and syntax)',
      },
      languages: {
        type: 'array',
        items: { type: 'string' },
        description: 'Limit scan to selected languages (javascript, typescript, python, go, rust, ruby, php, kotlin, etc.)',
      },
      ruleIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Run only selected rules (for example: ["BE-004", "FE-001", "LINT-001"])',
      },
      writeReport: {
        type: 'boolean',
        description: 'Write Security.md report (default: true)',
        default: true,
      },
      reportPath: {
        type: 'string',
        description: 'Security.md output path (default: <rootDir>/Security.md)',
      },
      maxMatchesPerFile: {
        type: 'number',
        description: 'Maximum findings per file (default: 50)',
      },
      ignore: {
        type: 'array',
        items: { type: 'string' },
        description: 'Glob patterns to ignore',
      },
      baselinePath: {
        type: 'string',
        description: 'Baseline file path -- show only NEW findings',
      },
      includeFixes: {
        type: 'boolean',
        description: 'Also summarize auto-fixable findings',
        default: false,
      },
    },
    required: [],
  },
};

export async function handleScanProject(args: Record<string, unknown> = {}): Promise<CallToolResult> {
  const params = args as {
    rootDir?: string;
    targetPath?: string;
    detailed?: boolean;
    layers?: Layer[];
    languages?: ScanOptions['languages'];
    ruleIds?: string[];
    writeReport?: boolean;
    reportPath?: string;
    maxMatchesPerFile?: number;
    ignore?: string[];
    baselinePath?: string;
    includeFixes?: boolean;
  };

  const opts: ScanOptions = {
    rootDir: params.rootDir ?? process.cwd(),
    targetPath: params.targetPath,
    detailed: params.detailed,
    layers: params.layers,
    languages: params.languages,
    ruleIds: params.ruleIds,
    maxMatchesPerFile: params.maxMatchesPerFile,
    ignore: params.ignore,
  };

  const result = await scan(opts);
  let displayFindings = result.findings;

  if (params.baselinePath) {
    const { readBaseline, diffAgainstBaseline } = await import('../engine/baseline.js');
    const baseline = await readBaseline(params.baselinePath);
    const diff = diffAgainstBaseline(result, baseline);
    displayFindings = diff.newFindings;
  }

  let reportPath: string | undefined;
  const writeReport = params.writeReport !== false;
  if (writeReport) {
    const filtered = { ...result, findings: displayFindings };
    reportPath = await writeSecurityReport(
      filtered,
      params.reportPath ?? `${result.rootDir}/Security.md`
    );
  }

  const summary = formatSummary({
    findings: displayFindings,
    summary: result.summary,
    filesScanned: result.filesScanned,
    rulesEvaluated: result.rulesEvaluated,
    durationMs: result.durationMs,
    targetPath: params.targetPath,
    detailed: params.detailed,
  });

  // Separate security findings from lint/language quality findings
  const securityFindings = displayFindings
    .filter((f) => f.layer !== 'lint')
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  const lintFindings = displayFindings
    .filter((f) => f.layer === 'lint')
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  const fixable = params.includeFixes
    ? displayFindings.filter((f) => f.fix).slice(0, 10)
    : [];

  const topSecurity = securityFindings.slice(0, 20);
  const topLint = lintFindings.slice(0, 15);

  const lines: string[] = [
    summary,
    '',
    reportPath ? `📝 Full Report written to: \`${reportPath}\`` : '',
    params.baselinePath ? `📋 Baseline diff: showing only NEW findings vs baseline` : '',
    '',
  ];

  if (topSecurity.length > 0) {
    lines.push('## 🛡️ Top Security Vulnerabilities');
    lines.push('');
    lines.push(
      topSecurity
        .map(
          (f) =>
            `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title} -- \`${f.file}:${f.match.line}\`${f.fix ? ' 🔧 (auto-fixable)' : ''}\n  *Action:* ${f.remediation.split('\n')[0]}`
        )
        .join('\n')
    );
    if (securityFindings.length > 20) {
      lines.push(`\n...and ${securityFindings.length - 20} more security findings (see Security.md).`);
    }
    lines.push('');
  } else {
    lines.push('✅ No critical or high security vulnerabilities found in scanned scope.\n');
  }

  if (topLint.length > 0) {
    lines.push('## 🧹 Language & Lint Quality Issues');
    lines.push('');
    lines.push(
      topLint
        .map(
          (f) =>
            `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title} -- \`${f.file}:${f.match.line}\`${f.fix ? ' 🔧' : ''}\n  *Detail:* ${f.description}`
        )
        .join('\n')
    );
    if (lintFindings.length > 15) {
      lines.push(`\n...and ${lintFindings.length - 15} more lint warnings (see Security.md).`);
    }
    lines.push('');
  }

  if (fixable.length > 0) {
    lines.push(`## 🔧 Auto-fixable Findings (${fixable.length})`);
    lines.push('');
    lines.push(
      fixable
        .map((f) => `### [\`${f.ruleId}\`] ${f.file}:${f.match.line}\n${f.fix!.description}\n`)
        .join('\n')
    );
    lines.push('💡 AI Agent can preview unified diffs or apply fixes via `apply_fix`.');
    lines.push('');
  }

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
    isError: false,
  };
}

function severityRank(s: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5;
}

function formatSummary(result: {
  findings: readonly Finding[];
  summary: { totalFindings: number; bySeverity: Record<string, number>; byLayer: Record<string, number> };
  filesScanned: number;
  rulesEvaluated: number;
  durationMs: number;
  targetPath?: string;
  detailed?: boolean;
}): string {
  const { bySeverity, byLayer } = result.summary;
  const lines: string[] = [];
  lines.push(`# Vibe Security Audit Complete`);
  lines.push('');
  if (result.targetPath) {
    lines.push(`- **Target Scope:** \`${result.targetPath}\``);
  }
  if (result.detailed) {
    lines.push(`- **Scan Mode:** 🔬 Detailed Deep Scan`);
  }
  lines.push(`- **Total findings:** ${result.summary.totalFindings}`);
  lines.push(`- **Files scanned:** ${result.filesScanned}`);
  lines.push(`- **Rules evaluated:** ${result.rulesEvaluated}`);
  lines.push(`- **Duration:** ${result.durationMs}ms`);
  lines.push('');
  lines.push('## By severity');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('| --- | --- |');
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    lines.push(`| ${sev} | ${bySeverity[sev] ?? 0} |`);
  }
  lines.push('');
  lines.push('## By layer');
  lines.push('');
  lines.push('| Layer | Count |');
  lines.push('| --- | --- |');
  for (const layer of ['frontend', 'backend', 'network', 'database', 'cicd', 'observability', 'lint']) {
    lines.push(`| ${layer} | ${byLayer[layer] ?? 0} |`);
  }
  return lines.join('\n');
}
