import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import { detectLanguage } from '../engine/language.js';
import { getRulesForLanguage } from '../engine/rules/index.js';
import type { Finding, Layer } from '../types.js';

export const scanFileToolDefinition = {
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
        description: 'Limit scan to selected layers',
      },
      ruleIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Run only selected rules',
      },
    },
  },
};

export async function handleScanFile(args: Record<string, unknown> = {}): Promise<CallToolResult> {
  const params = args as {
    filePath: string;
    layers?: Layer[];
    ruleIds?: string[];
  };

  if (!params.filePath) {
    return {
      content: [{ type: 'text', text: 'Error: filePath is required' }],
      isError: true,
    };
  }

  let source: string;
  try {
    source = await fs.readFile(params.filePath, 'utf8');
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error: Cannot read file: ${(err as Error).message}` }],
      isError: true,
    };
  }

  const language = detectLanguage(params.filePath, source);
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

  const findings: Finding[] = [];
  for (const rule of applicable) {
    try {
      for (const f of rule.check(ctx)) {
        findings.push(f);
      }
    } catch {
      // rule error skipped
    }
  }

  const formatted = findings.length
    ? findings
        .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
        .map(
          (f) =>
            `- **${f.severity.toUpperCase()}** [\`${f.ruleId}\`] ${f.title}\n  \`${f.file}:${f.match.line}\` -- ${f.match.snippet.trim().split('\n')[0]}${f.fix ? ' 🔧' : ''}`
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

function severityRank(s: string): number {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5;
}
