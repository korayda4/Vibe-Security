import path from 'node:path';
import { scan } from './scanner.js';
import { writeSecurityReport } from './reporter.js';
import { applyFixes, formatFixSummary } from './fixer.js';
import { loadConfig } from './config.js';
import type {
  Finding,
  ScanOptions,
  ScanResult,
  ScanSummary,
  Severity,
  BuildVerdict,
  BuildCheckOptions,
  BuildCheckResult,
} from '../types.js';

export type { BuildVerdict, BuildCheckOptions, BuildCheckResult };

export function formatSeverityBadge(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '🟣 [CRITICAL]';
    case 'high':
      return '🔴 [HIGH]';
    case 'medium':
      return '🟠 [MEDIUM]';
    case 'low':
      return '🟡 [LOW]';
    case 'info':
    default:
      return '🔵 [INFO]';
  }
}

const DEFAULT_BLOCK_SEVERITIES: readonly Severity[] = ['critical', 'high'];

export async function checkBuild(options: BuildCheckOptions = {}): Promise<BuildCheckResult> {
  const rootDir = options.rootDir ?? process.cwd();
  const blockSeverities = new Set(options.blockSeverities ?? DEFAULT_BLOCK_SEVERITIES);
  const shouldFix = Boolean(options.fix || options.autoPatch);
  const config = await loadConfig(rootDir);
  const ignore = options.ignore ?? config.ignore;

  // Run initial scan
  let scanResult = await scan({
    rootDir,
    targetPath: options.targetPath,
    detailed: options.detailed ?? true, // Build gate runs detailed by default
    layers: options.layers,
    languages: options.languages,
    ruleIds: options.ruleIds,
    ignore,
  });

  let appliedFixes: { file: string; ruleId: string; description: string }[] | undefined;
  let fixSummaryText: string | undefined;

  // If auto-patch / fix is requested, patch fixable vulnerabilities on the fly
  if (shouldFix) {
    const isDryRun = Boolean(options.dryRun);
    const fixableCount = scanResult.findings.filter((f) => Boolean(f.fix)).length;
    if (fixableCount > 0) {
      const fixSummary = await applyFixes(scanResult, {
        dryRun: isDryRun,
        onlyRuleIds: options.ruleIds,
      });

      appliedFixes = fixSummary.applied.map((a) => ({
        file: a.file,
        ruleId: a.ruleId,
        description: a.description,
      }));
      fixSummaryText = formatFixSummary(fixSummary, isDryRun);

      // Re-scan after applying patches to disk so the build verdict reflects cleaned state
      if (!isDryRun && fixSummary.applied.length > 0) {
        scanResult = await scan({
          rootDir,
          targetPath: options.targetPath,
          detailed: options.detailed ?? true,
          layers: options.layers,
          languages: options.languages,
          ruleIds: options.ruleIds,
          ignore,
        });
      }
    }
  }

  const blockingFindings: Finding[] = [];
  const warningFindings: Finding[] = [];

  for (const finding of scanResult.findings) {
    if (blockSeverities.has(finding.severity)) {
      blockingFindings.push(finding);
    } else {
      warningFindings.push(finding);
    }
  }

  const criticalCount = scanResult.summary.bySeverity.critical ?? 0;
  const highCount = scanResult.summary.bySeverity.high ?? 0;
  const warningCount = warningFindings.length;

  let verdict: BuildVerdict;
  let exitCode: number;

  if (blockingFindings.length > 0) {
    verdict = 'SECURITY_VULNERABILITY';
    exitCode = 1;
  } else if (warningFindings.length > 0) {
    verdict = 'WARNING';
    exitCode = 0;
  } else {
    verdict = 'SUCCESS';
    exitCode = 0;
  }

  let reportPath: string | undefined;
  if (options.writeReport !== false) {
    const targetReport = options.reportPath ?? path.join(rootDir, 'Security.md');
    reportPath = await writeSecurityReport(scanResult, targetReport);
  }

  const terminalOutput = renderTerminalOutput({
    verdict,
    scanResult,
    blockingFindings,
    warningFindings,
    reportPath,
    criticalCount,
    highCount,
    warningCount,
    appliedFixes,
    fixSummaryText,
    isDryRun: options.dryRun,
  });

  return {
    verdict,
    exitCode,
    scanResult,
    summary: scanResult.summary,
    criticalCount,
    highCount,
    warningCount,
    blockingCount: blockingFindings.length,
    blockingFindings,
    warningFindings,
    reportPath,
    terminalOutput,
    appliedFixes,
    fixSummary: fixSummaryText,
  };
}

function renderTerminalOutput(params: {
  verdict: BuildVerdict;
  scanResult: ScanResult;
  blockingFindings: readonly Finding[];
  warningFindings: readonly Finding[];
  reportPath?: string;
  criticalCount: number;
  highCount: number;
  warningCount: number;
  appliedFixes?: readonly { file: string; ruleId: string; description: string }[];
  fixSummaryText?: string;
  isDryRun?: boolean;
}): string {
  const {
    verdict,
    blockingFindings,
    warningFindings,
    reportPath,
    criticalCount,
    highCount,
    warningCount,
    appliedFixes,
    fixSummaryText,
    isDryRun,
  } = params;
  const lines: string[] = [];

  const hr = '━'.repeat(64);

  // If patches were applied or previewed, display patch summary first
  if (appliedFixes && appliedFixes.length > 0) {
    lines.push(hr);
    if (isDryRun) {
      lines.push(`🔍 [Pre-Build Patch Preview] ${appliedFixes.length} patch(es) ready to apply:`);
    } else {
      lines.push(`🔧 [Pre-Build Auto-Patch] Applied ${appliedFixes.length} security patch(es) on-the-fly:`);
    }
    for (const p of appliedFixes) {
      lines.push(`  • [${p.ruleId}] ${p.file}: ${p.description}`);
    }
    lines.push(hr);
  }

  if (verdict === 'SUCCESS') {
    lines.push(hr);
    lines.push('✅ [SecurityCheckBuild: SUCCESS] All Security & Quality Checks Passed!');
    lines.push(hr);
    lines.push(`• Files audited: ${params.scanResult.filesScanned}`);
    lines.push(`• Rules evaluated: ${params.scanResult.rulesEvaluated}`);
    lines.push(`• Duration: ${params.scanResult.durationMs}ms`);
    if (appliedFixes && appliedFixes.length > 0) {
      lines.push(`• Auto-patches applied: ${appliedFixes.length} (vulnerabilities healed)`);
    }
    lines.push('• Result: 0 blocking vulnerabilities. Build proceeding safely.');
    lines.push(hr);
  } else if (verdict === 'WARNING') {
    lines.push(hr);
    lines.push(`⚠️  [SecurityCheckBuild: WARNING] ${warningCount} Non-blocking Issue(s) Detected`);
    lines.push(hr);
    lines.push(`• Files audited: ${params.scanResult.filesScanned}`);
    lines.push(`• Non-blocking warnings: ${warningCount}`);
    if (appliedFixes && appliedFixes.length > 0) {
      lines.push(`• Auto-patches applied: ${appliedFixes.length}`);
    }
    lines.push('• Status: No Critical or High vulnerabilities. Build proceeding with warnings.');
    lines.push('');
    lines.push('⚠️  Affected Files & Severity Breakdown:');

    // Group warnings by file
    const byFile = new Map<string, Finding[]>();
    for (const f of warningFindings) {
      const arr = byFile.get(f.file) ?? [];
      arr.push(f);
      byFile.set(f.file, arr);
    }

    for (const [file, fList] of byFile.entries()) {
      const sevCounts = fList.reduce((acc, curr) => {
        acc[curr.severity] = (acc[curr.severity] ?? 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      const sevSummary = Object.entries(sevCounts)
        .map(([s, c]) => `${s.toUpperCase()}: ${c}`)
        .join(', ');

      lines.push(`  📁 ${file} (${sevSummary})`);
      for (const f of fList) {
        const badge = formatSeverityBadge(f.severity);
        lines.push(`     ${badge} Line ${f.match.line} [\`${f.ruleId}\`] ${f.title}`);
      }
      lines.push('');
    }

    lines.push(`💡 Run 'npx vibe-security scan .' or '/securityCheck' to inspect & clean up warnings.`);
    if (reportPath) lines.push(`📝 Full details written to: ${reportPath}`);
    lines.push(hr);
  } else {
    lines.push(hr);
    lines.push('🚨 [SecurityCheckBuild: SECURITY VULNERABILITY - BUILD BLOCKED]');
    lines.push(hr);
    const blockingSevCounts = blockingFindings.reduce((acc, curr) => {
      acc[curr.severity] = (acc[curr.severity] ?? 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const sevParts: string[] = [];
    for (const s of ['critical', 'high', 'medium', 'low', 'info'] as const) {
      if (blockingSevCounts[s]) {
        sevParts.push(`${blockingSevCounts[s]} ${s.charAt(0).toUpperCase() + s.slice(1)}`);
      }
    }
    const sevBreakdown = sevParts.length > 0 ? sevParts.join(' and ') : `${blockingFindings.length} Unspecified`;

    lines.push(
      `❌ BUILD HALTED: Found ${blockingFindings.length} blocking vulnerabilit${blockingFindings.length === 1 ? 'y' : 'ies'} (${sevBreakdown})!`
    );
    lines.push('Production build is blocked to prevent deploying security flaws.');
    lines.push('');
    lines.push('🚨 Blocking Vulnerabilities by File & Severity:');

    // Group blocking findings by file
    const byFile = new Map<string, Finding[]>();
    for (const f of blockingFindings) {
      const arr = byFile.get(f.file) ?? [];
      arr.push(f);
      byFile.set(f.file, arr);
    }

    for (const [file, fList] of byFile.entries()) {
      const sevCounts = fList.reduce((acc, curr) => {
        acc[curr.severity] = (acc[curr.severity] ?? 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      const sevSummary = Object.entries(sevCounts)
        .map(([s, c]) => `${s.toUpperCase()}: ${c}`)
        .join(', ');

      lines.push(`  📁 ${file} (${sevSummary})`);
      for (const f of fList) {
        const badge = formatSeverityBadge(f.severity);
        lines.push(`     ${badge} Line ${f.match.line} [\`${f.ruleId}\`] ${f.title}`);
        lines.push(`        Threat: ${f.impact}`);
        lines.push(`        Action: ${f.remediation.split('\n')[0]}`);
        if (f.fix) {
          lines.push(`        🔧 Auto-fixable: ${f.fix.description}`);
        }
      }
      lines.push('');
    }

    lines.push('To unblock the build:');
    lines.push('  1) Run `npx vibe-security check-build . --fix` to auto-apply security patches.');
    lines.push('  2) Or run `/securityCheck --fix` in your AI coding assistant to auto-remediate.');
    lines.push('  3) Re-run build once vulnerabilities are resolved.');
    if (reportPath) lines.push(`\n📝 Audit report: ${reportPath}`);
    lines.push(hr);
  }

  return lines.join('\n');
}
