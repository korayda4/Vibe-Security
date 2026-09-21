import path from 'node:path';
import { scan } from './scanner.js';
import { writeSecurityReport } from './reporter.js';
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

const DEFAULT_BLOCK_SEVERITIES: readonly Severity[] = ['critical', 'high'];

export async function checkBuild(options: BuildCheckOptions = {}): Promise<BuildCheckResult> {
  const rootDir = options.rootDir ?? process.cwd();
  const blockSeverities = new Set(options.blockSeverities ?? DEFAULT_BLOCK_SEVERITIES);

  // Run comprehensive scan
  const scanResult = await scan({
    rootDir,
    targetPath: options.targetPath,
    detailed: options.detailed ?? true, // Build gate runs detailed by default
    layers: options.layers,
    languages: options.languages,
    ruleIds: options.ruleIds,
    ignore: options.ignore,
  });

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
  });

  return {
    verdict,
    exitCode,
    scanResult,
    summary: scanResult.summary,
    criticalCount,
    highCount,
    warningCount,
    blockingFindings,
    warningFindings,
    reportPath,
    terminalOutput,
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
}): string {
  const { verdict, blockingFindings, warningFindings, reportPath, criticalCount, highCount, warningCount } = params;
  const lines: string[] = [];

  const hr = '━'.repeat(64);

  if (verdict === 'SUCCESS') {
    lines.push(hr);
    lines.push('✅ [SecurityCheckBuild: SUCCESS] All Security & Quality Checks Passed!');
    lines.push(hr);
    lines.push(`• Files audited: ${params.scanResult.filesScanned}`);
    lines.push(`• Rules evaluated: ${params.scanResult.rulesEvaluated}`);
    lines.push(`• Duration: ${params.scanResult.durationMs}ms`);
    lines.push('• Result: 0 vulnerabilities found. Build proceeding safely.');
    lines.push(hr);
  } else if (verdict === 'WARNING') {
    lines.push(hr);
    lines.push(`⚠️  [SecurityCheckBuild: WARNING] ${warningCount} Non-blocking Issue(s) Detected`);
    lines.push(hr);
    lines.push(`• Files audited: ${params.scanResult.filesScanned}`);
    lines.push(`• Non-blocking warnings: ${warningCount}`);
    lines.push('• Status: No Critical or High vulnerabilities. Build proceeding with warnings.');
    lines.push('');
    lines.push('Top Warnings:');
    for (const f of warningFindings.slice(0, 5)) {
      lines.push(`  [${f.severity.toUpperCase()}] [${f.ruleId}] ${f.file}:${f.match.line} - ${f.title}`);
    }
    if (warningFindings.length > 5) {
      lines.push(`  ...and ${warningFindings.length - 5} more warnings.`);
    }
    lines.push('');
    lines.push(`💡 Run 'npx vibe-security scan .' or '/securityCheck' to inspect & clean up warnings.`);
    if (reportPath) lines.push(`📝 Full details written to: ${reportPath}`);
    lines.push(hr);
  } else {
    lines.push(hr);
    lines.push('🚨 [SecurityCheckBuild: SECURITY VULNERABILITY - BUILD BLOCKED]');
    lines.push(hr);
    lines.push(`❌ BUILD HALTED: Found ${criticalCount} Critical and ${highCount} High vulnerabilities!`);
    lines.push('Production build is blocked to prevent deploying security flaws.');
    lines.push('');
    lines.push('Blocking Flaws:');
    for (const f of blockingFindings) {
      lines.push(`  🔴 [${f.severity.toUpperCase()}] [\`${f.ruleId}\`] ${f.file}:${f.match.line}`);
      lines.push(`     Title: ${f.title}`);
      lines.push(`     Threat: ${f.impact}`);
      lines.push(`     Action: ${f.remediation.split('\n')[0]}`);
      if (f.fix) {
        lines.push(`     🔧 Auto-fixable: ${f.fix.description}`);
      }
      lines.push('');
    }
    lines.push('To unblock the build:');
    lines.push('  1) Run `npx vibe-security scan . --fix --dry-run` to inspect auto-fixes.');
    lines.push('  2) Or run `/securityCheck --fix` in your AI coding assistant to auto-remediate.');
    lines.push('  3) Re-run build once vulnerabilities are resolved.');
    if (reportPath) lines.push(`\n📝 Audit report: ${reportPath}`);
    lines.push(hr);
  }

  return lines.join('\n');
}
