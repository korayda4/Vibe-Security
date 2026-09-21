import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { scan } from '../engine/scanner.js';
import { writeSecurityReport } from '../engine/reporter.js';
import type { Layer, ScanOptions } from '../types.js';

export const scanProjectToolDefinition = {
  name: 'scan_project',
  description:
    'Scan the entire project for security vulnerabilities across all layers and languages. Returns findings summary and top findings.',
  inputSchema: {
    type: 'object',
    properties: {
      rootDir: {
        type: 'string',
        description: 'Directory to scan (default: cwd)',
      },
      layers: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability'],
        },
        description: 'Limit scan to selected layers',
      },
      languages: {
        type: 'array',
        items: { type: 'string' },
        description: 'Limit scan to selected languages (javascript, typescript, python, etc.)',
      },
      ruleIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Run only selected rules (for example: ["BE-004", "FE-001"])',
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

  const summary = formatSummary({ ...result, findings: displayFindings });
  const topFindings = displayFindings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 30);
  const fixable = params.includeFixes
    ? displayFindings.filter((f) => f.fix).slice(0, 10)
    : [];

  const text = [
    summary,
    '',
    reportPath ? `📝 Report written to: \`${reportPath}\`` : '',
    params.baselinePath ? `\n📋 Baseline diff: showing only NEW findings` : '',
    '',
    '## Top Findings',
    '',
    topFindings
      .map(
        (f) =>
          `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title} -- \`${f.file}:${f.match.line}\`${f.fix ? ' 🔧 (auto-fixable)' : ''}`
      )
      .join('\n'),
    displayFindings.length > 30
      ? `\n\n...and ${displayFindings.length - 30} more (see Security.md).`
      : '',
    fixable.length > 0
      ? `\n\n## 🔧 Auto-fixable (${fixable.length})\n\n` +
        fixable
          .map((f) => `### [\`${f.ruleId}\`] ${f.file}:${f.match.line}\n${f.fix!.description}\n`)
          .join('\n')
      : '',
    fixable.length > 0
      ? `\n💡 AI Agent can preview or apply via the \`apply_fix\` MCP tool.`
      : '',
  ]
    .filter(Boolean)
    .join('\n');

  return {
    content: [{ type: 'text', text }],
    isError: false,
  };
}

function severityRank(s: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5;
}

function formatSummary(result: {
  findings: readonly { severity: string }[];
  summary: { totalFindings: number; bySeverity: Record<string, number>; byLayer: Record<string, number> };
  filesScanned: number;
  rulesEvaluated: number;
  durationMs: number;
}): string {
  const { bySeverity, byLayer } = result.summary;
  const lines: string[] = [];
  lines.push(`# Vibe Security Scan Complete`);
  lines.push('');
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
  for (const layer of ['frontend', 'backend', 'network', 'database', 'cicd', 'observability']) {
    lines.push(`| ${layer} | ${byLayer[layer] ?? 0} |`);
  }
  return lines.join('\n');
}
