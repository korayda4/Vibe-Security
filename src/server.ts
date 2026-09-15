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
    version: '0.1.0',
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
          'Tum projeyi guvenlik acisindan tarar. Butun kurallari uygular, bulgulari kategorize eder ve istege bagli olarak Security.md raporu yazar.',
        inputSchema: {
          type: 'object',
          properties: {
            rootDir: {
              type: 'string',
              description: 'Taranacak dizin (default: cwd)',
            },
            layers: {
              type: 'array',
              items: {
                type: 'string',
                enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability'],
              },
              description: 'Taramayi bu katmanlarla sinirla',
            },
            languages: {
              type: 'array',
              items: { type: 'string' },
              description: 'Belirli dillere kisitla (javascript, python, java, go, vb.)',
            },
            ruleIds: {
              type: 'array',
              items: { type: 'string' },
              description: 'Sadece belirli kurallari calistir (ornek: ["BE-004", "FE-001"])',
            },
            writeReport: {
              type: 'boolean',
              description: 'Security.md dosyasi yaz (default: true)',
              default: true,
            },
            reportPath: {
              type: 'string',
              description: 'Security.md cikti yolu (default: <rootDir>/Security.md)',
            },
            maxMatchesPerFile: {
              type: 'number',
              description: 'Dosya basina maks. eslesme (default: 50)',
            },
            ignore: {
              type: 'array',
              items: { type: 'string' },
              description: 'HariÃ§ tutulacak glob desenleri',
            },
            baselinePath: {
              type: 'string',
              description: 'Baseline dosyasi â€” sadece yeni bulgulari gosterir',
            },
            includeFixes: {
              type: 'boolean',
              description: 'Auto-fixable bulgulari da ozet olarak goster',
              default: false,
            },
          },
          required: [],
        },
      },
      {
        name: 'scan_file',
        description:
          'Tek bir dosyayi belirli kurallarla tarar. Belirli bir bulguyu dogrulamak veya yeni eklenen dosyayi hizla kontrol etmek icin kullan.',
        inputSchema: {
          type: 'object',
          required: ['filePath'],
          properties: {
            filePath: {
              type: 'string',
              description: 'Taranacak dosyanin mutlak yolu',
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
          'Mevcut tum guvenlik kurallarini listeler. ID, katman, severity, baslik ve dil destegi icerir.',
        inputSchema: {
          type: 'object',
          properties: {
            layer: {
              type: 'string',
              enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability'],
              description: 'Belirli bir katmana filtrele',
            },
          },
        },
      },
      {
        name: 'get_rule_detail',
        description:
          'Belirli bir kural hakkinda tam detay: aciklama, tehdit, onlem, referanslar, ornek desenler.',
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
        reportPath ? `ğŸ“ Report written to: \`${reportPath}\`` : '',
        params.baselinePath ? `\nğŸ“‹ Baseline diff: showing only NEW findings` : '',
        '',
        '## Top Findings',
        '',
        topFindings
          .map(
            (f) =>
              `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title} â€” \`${f.file}:${f.match.line}\`${f.fix ? ' ğŸ”§' : ''}`
          )
          .join('\n'),
        displayFindings.length > 30
          ? `\n\nâ€¦and ${displayFindings.length - 30} more (see Security.md).`
          : '',
        fixable.length > 0
          ? `\n\n## ğŸ”§ Auto-fixable (${fixable.length})\n\n` +
            fixable
              .map((f) => `### [\`${f.ruleId}\`] ${f.file}:${f.match.line}\n${f.fix!.description}\n`)
              .join('\n')
          : '',
        fixable.length > 0
          ? `\nKullanici isterse \`vibe-security scan . --fix --dry-run\` ile uygulayabilir.`
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
                `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title}\n  \`${f.file}:${f.match.line}\` â€” ${f.match.snippet.trim().split('\n')[0]}`
            )
            .join('\n')
        : 'âœ… No findings for this file with the selected rules.';

      return {
        content: [
          {
            type: 'text',
            text: `# File Scan â€” ${path.basename(params.filePath)}\n\nLanguage: \`${language}\`\nRules applied: ${applicable.length}\nFindings: ${findings.length}\n\n${formatted}`,
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
            `- [\`${r.id}\`] **${r.severity.toUpperCase()}** Â· ${r.layer} Â· ${r.title}\n  Languages: ${r.languages.join(', ')}`
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
        `# ${rule.id} â€” ${rule.title}`,
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
  lines.push(`# ğŸ›¡ï¸ Vibe Security Scan Complete`);
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
    content: [{ type: 'text', text: `âŒ ${message}` }],
    isError: true,
  };
}

export async function startServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[vibe-security] MCP server running on stdio');
}
