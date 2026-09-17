import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';

import { scan } from './engine/scanner.js';
import { writeSecurityReport } from './engine/reporter.js';
import { getAllRules, getRuleById } from './engine/rules/index.js';
import type { Layer, ScanOptions } from './types.js';

export const server = new Server(
  {
    name: 'vibe-security',
    version: '1.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'scan_project',
        description:
          'Scan the entire project. Applies all rules, categorizes findings, and optionally writes a Security.md report.',
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
              description: 'Limit the scan to these layers',
            },
            languages: {
              type: 'array',
              items: { type: 'string' },
              description: 'Limit the scan to selected languages (for example: javascript, python, java, go)',
            },
            ruleIds: {
              type: 'array',
              items: { type: 'string' },
              description: 'Run only selected rules (for example: ["BE-004", "FE-001"])',
            },
            writeReport: {
              type: 'boolean',
              description: 'Write Security.md (default: true)',
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
              description: 'Baseline file -- show only NEW findings',
            },
            includeFixes: {
              type: 'boolean',
              description: 'Also summarize auto-fixable findings',
              default: false,
            },
          },
          required: [],
        },
      },
      {
        name: 'scan_file',
        description:
          'Scan a single file with selected rules. Use this to validate a specific finding or quickly check a newly-added file.',
        inputSchema: {
          type: 'object',
          required: ['filePath'],
          properties: {
            filePath: {
              type: 'string',
              description: 'Absolute path of the file to scan',
            },
            layers: {
              type: 'array',
              items: { type: 'string' },
            },
            ruleIds: {
              type: 'array',
              items: { type: 'string' },
            },
          },
        },
      },
      {
        name: 'list_rules',
        description:
          'List all security rules with their ID, layer, severity, title, and supported languages.',
        inputSchema: {
          type: 'object',
          properties: {
            layer: {
              type: 'string',
              enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability'],
              description: 'Filter by layer',
            },
          },
        },
      },
      {
        name: 'get_rule_detail',
        description:
          'Show full details for a rule, including description, threat, remediation, and references.',
        inputSchema: {
          type: 'object',
          required: ['ruleId'],
          properties: {
            ruleId: {
              type: 'string',
              description: 'Kural ID (ornek: "BE-004", "FE-001")',
            },
          },
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'scan_project': {
      const params = (args ?? {}) as {
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
        const { readBaseline, diffAgainstBaseline } = await import('./engine/baseline.js');
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
      const profileSection = result.profile
        ? `\n## Project Profile\n\n- **Primary language:** \`${result.profile.primary}\`\n- **Languages detected:** ${result.profile.detected.map((l) => `\`${l}\``).join(', ')}\n- **Applicable rules:** ${result.profile.applicableRules.length}\n`
        : '';
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
              `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title} -- \`${f.file}:${f.match.line}\`${f.fix ? ' 🔧' : ''}`
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
          ? `\nUser can apply via \`vibe-security scan . --fix --dry-run\`.`
          : '',
      ]
        .filter(Boolean)
        .join('\n');

      return {
        content: [{ type: 'text', text }],
        isError: false,
      };
    }

    case 'scan_file': {
      const params = (args ?? {}) as {
        filePath: string;
        layers?: Layer[];
        ruleIds?: string[];
      };

      if (!params.filePath) {
        return errorResult('filePath is required');
      }

      const fs = await import('node:fs/promises');
      const path = await import('node:path');
      const { detectLanguage } = await import('./engine/language.js');
      const { getRulesForLanguage } = await import('./engine/rules/index.js');
      const { makeFinding } = await import('./engine/rules/_helpers.js');

      let source: string;
      try {
        source = await fs.readFile(params.filePath, 'utf8');
      } catch (err) {
        return errorResult(`Cannot read file: ${(err as Error).message}`);
      }

      const language = detectLanguage(params.filePath);
      const candidates = getRulesForLanguage(language);
      const applicable = candidates.filter((r) => {
        if (params.ruleIds && !params.ruleIds.includes(r.id)) return false;
        if (params.layers && !params.layers.includes(r.layer)) return false;
        return true;
      });

      const lines = source.split(/\r?\n/);
      const ctx = {
        filePath: params.filePath,
        relativePath: path.relative(process.cwd(), params.filePath),
        language,
        source,
        lines,
      };

      const findings = [];
      for (const rule of applicable) {
        try {
          for (const f of rule.check(ctx)) {
            findings.push(f);
          }
        } catch {
}
      }

      const formatted = findings.length
        ? findings
            .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
            .map(
              (f) =>
                `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title}\n  \`${f.file}:${f.match.line}\` -- ${f.match.snippet.trim().split('\n')[0]}`
            )
            .join('\n')
        : '✅ No findings for this file with the selected rules.';

      return {
        content: [
          {
            type: 'text',
            text: `# File Scan -- ${path.basename(params.filePath)}\n\nLanguage: \`${language}\`\nRules applied: ${applicable.length}\nFindings: ${findings.length}\n\n${formatted}`,
          },
        ],
        isError: false,
      };
    }

    case 'list_rules': {
      const params = (args ?? {}) as { layer?: Layer };
      const rules = params.layer
        ? getAllRules().filter((r) => r.layer === params.layer)
        : getAllRules();

      const text = rules
        .map(
          (r) =>
            `- [\`${r.id}\`] **${r.severity.toUpperCase()}** - ${r.layer} - ${r.title}\n  Languages: ${r.languages.join(', ')}`
        )
        .join('\n');

      return {
        content: [
          {
            type: 'text',
            text: `# Available Security Rules\n\nTotal: ${rules.length}\n\n${text}`,
          },
        ],
        isError: false,
      };
    }

    case 'get_rule_detail': {
      const params = (args ?? {}) as { ruleId: string };
      const rule = getRuleById(params.ruleId);
      if (!rule) {
        return errorResult(`Rule not found: ${params.ruleId}`);
      }
      const text = [
        `# ${rule.id} -- ${rule.title}`,
        '',
        `- **Layer:** ${rule.layer}`,
        `- **Severity:** ${rule.severity}`,
        rule.cwe ? `- **CWE:** ${rule.cwe}` : '',
        rule.owasp ? `- **OWASP:** ${rule.owasp}` : '',
        `- **Languages:** ${rule.languages.join(', ')}`,
        '',
        '## Description',
        '',
        rule.description,
        '',
        '## Threat / Impact',
        '',
        rule.threat,
        '',
        '## Remediation',
        '',
        rule.remediation,
        '',
        rule.references.length > 0
          ? `## References\n\n${rule.references.map((r) => `- ${r}`).join('\n')}`
          : '',
      ]
        .filter(Boolean)
        .join('\n');

      return {
        content: [{ type: 'text', text }],
        isError: false,
      };
    }

    default:
      return errorResult(`Unknown tool: ${name}`);
  }
});

function severityRank(s: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5;
}

function formatSummary(result: { findings: readonly { severity: string }[]; summary: { totalFindings: number; bySeverity: Record<string, number>; byLayer: Record<string, number> }; filesScanned: number; rulesEvaluated: number; durationMs: number }): string {
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

function errorResult(message: string): CallToolResult {
  return {
    content: [{ type: 'text', text: `Error: ${message}` }],
    isError: true,
  };
}

export async function startServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[vibe-security] MCP server running on stdio');
}
