import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { checkBuild, type BuildCheckOptions } from '../engine/buildGuard.js';
import type { Layer, Language, Severity } from '../types.js';

export const checkBuildToolDefinition = {
  name: 'check_build',
  description:
    'Pre-build security gate. Automatically audits project or targeted paths before build and returns a 3-tier verdict: SUCCESS (clean, proceed), WARNING (non-blocking issues found, proceed with warnings), or SECURITY_VULNERABILITY (critical/high vulnerabilities found, build halted).',
  inputSchema: {
    type: 'object',
    properties: {
      rootDir: {
        type: 'string',
        description: 'Project root directory to verify (default: current directory)',
      },
      targetPath: {
        type: 'string',
        description: 'Specific subdirectory or component to check (e.g. "src", "backend", "client")',
      },
      detailed: {
        type: 'boolean',
        description: 'Run deep scan with elevated limits (default: true)',
        default: true,
      },
      writeReport: {
        type: 'boolean',
        description: 'Whether to write/update Security.md (default: true)',
        default: true,
      },
      reportPath: {
        type: 'string',
        description: 'Custom path for the Markdown report (default: <rootDir>/Security.md)',
      },
      blockSeverities: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['critical', 'high', 'medium', 'low', 'info'],
        },
        description: 'Severities that block the build (default: ["critical", "high"])',
      },
      layers: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['frontend', 'backend', 'network', 'database', 'cicd', 'observability', 'lint'],
        },
        description: 'Limit build check to selected layers',
      },
      languages: {
        type: 'array',
        items: { type: 'string' },
        description: 'Limit build check to selected programming languages',
      },
      ruleIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Limit build check to specific rule IDs',
      },
      fix: {
        type: 'boolean',
        description: 'Automatically apply patches for fixable vulnerabilities on the fly to unblock the build',
        default: false,
      },
      dryRun: {
        type: 'boolean',
        description: 'Preview auto-fixes without writing changes to disk',
        default: false,
      },
    },
  },
};

export async function handleCheckBuild(
  rawArgs: Record<string, unknown>
): Promise<CallToolResult> {
  try {
    const rootDir = typeof rawArgs.rootDir === 'string' ? rawArgs.rootDir : process.cwd();
    const targetPath = typeof rawArgs.targetPath === 'string' ? rawArgs.targetPath : undefined;
    const detailed = typeof rawArgs.detailed === 'boolean' ? rawArgs.detailed : true;
    const writeReport = typeof rawArgs.writeReport === 'boolean' ? rawArgs.writeReport : true;
    const reportPath = typeof rawArgs.reportPath === 'string' ? rawArgs.reportPath : undefined;
    const fix = Boolean(rawArgs.fix || rawArgs.autoPatch);
    const dryRun = Boolean(rawArgs.dryRun);
    const blockSeverities = Array.isArray(rawArgs.blockSeverities)
      ? (rawArgs.blockSeverities as Severity[])
      : undefined;
    const layers = Array.isArray(rawArgs.layers) ? (rawArgs.layers as Layer[]) : undefined;
    const languages = Array.isArray(rawArgs.languages) ? (rawArgs.languages as Language[]) : undefined;
    const ruleIds = Array.isArray(rawArgs.ruleIds) ? (rawArgs.ruleIds as string[]) : undefined;

    const result = await checkBuild({
      rootDir,
      targetPath,
      detailed,
      writeReport,
      reportPath,
      blockSeverities,
      layers,
      languages,
      ruleIds,
      fix,
      dryRun,
    });

    const isBlocked = result.verdict === 'SECURITY_VULNERABILITY';

    const responsePayload = {
      verdict: result.verdict,
      exitCode: result.exitCode,
      status: isBlocked ? 'BLOCKED' : 'PASSED',
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      warningCount: result.warningCount,
      totalFindings: result.scanResult.findings.length,
      reportPath: result.reportPath,
      appliedFixes: result.appliedFixes,
      fixSummary: result.fixSummary,
      blockingCount: result.blockingFindings.length,
      blockingFindings: result.blockingFindings.map((f) => ({
        id: f.id,
        ruleId: f.ruleId,
        severity: f.severity,
        file: f.file,
        line: f.match.line,
        title: f.title,
        impact: f.impact,
        fixable: Boolean(f.fix),
      })),
      warningFindings: result.warningFindings.map((f) => ({
        id: f.id,
        ruleId: f.ruleId,
        severity: f.severity,
        file: f.file,
        line: f.match.line,
        title: f.title,
      })),
    };

    return {
      content: [
        {
          type: 'text',
          text: result.terminalOutput,
        },
        {
          type: 'text',
          text: JSON.stringify(responsePayload, null, 2),
        },
      ],
      isError: isBlocked,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: 'text', text: `Build check error: ${message}` }],
      isError: true,
    };
  }
}
