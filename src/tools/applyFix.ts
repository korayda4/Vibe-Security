import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import path from 'node:path';
import { scan } from '../engine/scanner.js';
import { applyFixes, formatFixSummary } from '../engine/fixer.js';

export const applyFixToolDefinition = {
  name: 'apply_fix',
  description:
    'Preview or apply automated security patches to fix vulnerabilities in the project. By default runs in dry-run mode (safe preview). Pass dryRun: false to write modifications to disk.',
  inputSchema: {
    type: 'object',
    properties: {
      rootDir: {
        type: 'string',
        description: 'Project root directory (default: cwd)',
      },
      ruleIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Limit fixes to specific rule IDs (e.g. ["FE-001", "NET-001"])',
      },
      file: {
        type: 'string',
        description: 'Limit fixes to a specific file (relative path)',
      },
      dryRun: {
        type: 'boolean',
        description: 'If true, preview changes with unified diff without modifying files on disk. Set false to apply (default: true)',
        default: true,
      },
    },
  },
};

export async function handleApplyFix(args: Record<string, unknown> = {}): Promise<CallToolResult> {
  const rootDir = typeof args.rootDir === 'string' ? path.resolve(args.rootDir) : process.cwd();
  const dryRun = args.dryRun !== false; // defaults to true for safety
  const ruleIds = Array.isArray(args.ruleIds) ? (args.ruleIds as string[]) : undefined;
  const fileFilter = typeof args.file === 'string' ? args.file : undefined;

  // Run scan to get current findings with fix patches
  const scanResult = await scan({
    rootDir,
    ruleIds,
  });

  const targetResult = fileFilter
    ? {
        ...scanResult,
        findings: scanResult.findings.filter((f) => f.file === fileFilter || f.file.endsWith(fileFilter)),
      }
    : scanResult;

  const fixSummary = await applyFixes(targetResult, {
    dryRun,
    onlyRuleIds: ruleIds,
  });

  const formatted = formatFixSummary(fixSummary, dryRun);
  const statusLine = dryRun
    ? `> **Dry Run Mode:** No files were changed on disk. To apply these patches, run with \`dryRun: false\`.`
    : `> **Applied:** Modified ${fixSummary.applied.length} file(s) on disk.`;

  return {
    content: [
      {
        type: 'text',
        text: `${statusLine}\n\n${formatted}`,
      },
    ],
    isError: false,
  };
}
