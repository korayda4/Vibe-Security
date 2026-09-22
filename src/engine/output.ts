import type { ScanResult, Severity } from '../types.js';

export function toSarif(result: ScanResult): unknown {
  const rules = new Map<
    string,
    { id: string; name: string; helpText: string; helpUri?: string; defaultSeverity: Severity }
  >();

  for (const f of result.findings) {
    if (rules.has(f.ruleId)) continue;
    rules.set(f.ruleId, {
      id: f.ruleId,
      name: f.title,
      helpText: f.remediation,
      helpUri: f.references[0],
      defaultSeverity: f.severity,
    });
  }

  const sarifRules = Array.from(rules.values()).map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: r.name },
    fullDescription: { text: r.helpText },
    help: { text: r.helpText },
    helpUri: r.helpUri,
    defaultConfiguration: { level: severityToSarifLevel(r.defaultSeverity) },
  }));

  const sarifResults = result.findings.map((f) => ({
    ruleId: f.ruleId,
    level: severityToSarifLevel(f.severity),
    message: { text: `${f.title} -- ${f.impact}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: {
            startLine: f.match.line,
            startColumn: f.match.column + 1,
            snippet: { text: f.match.snippet.trim() },
          },
        },
      },
    ],
    fixes: f.fix
      ? [
          {
            description: { text: f.fix.description },
            artifactChanges: [
              {
                artifactLocation: { uri: f.file },
                replacements: [
                  {
                    deletedRegion: { snippet: { text: f.fix.find } },
                    insertedText: { text: f.fix.replace },
                  },
                ],
              },
            ],
          },
        ]
      : undefined,
  }));

  return {
    $schema: 'https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Vibe Security',
            version: '1.3.4',
            informationUri: 'https://github.com/korayda4/Vibe-Security',
            rules: sarifRules,
          },
        },
        originalUriBaseIds: { SRCROOT: { uri: 'file://' + result.rootDir + '/' } },
        results: sarifResults,
        invocations: [
          {
            startTimeUtc: result.startedAt,
            endTimeUtc: result.finishedAt,
            executionSuccessful: true,
          },
        ],
      },
    ],
  };
}

function severityToSarifLevel(s: Severity): string {
  switch (s) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'note';
  }
}

export function toJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function toJunit(result: ScanResult): string {
  const cases = result.findings.map(
    (f) =>
      `    <testcase classname="${escapeXml(f.layer)}" name="${escapeXml(f.ruleId)} ${escapeXml(f.title)}" time="0">\n` +
      `      <failure type="${escapeXml(f.severity)}" message="${escapeXml(f.title)}">\n` +
      `        ${escapeXml(f.file)}:${f.match.line} -- ${escapeXml(f.impact)}\n` +
      `      </failure>\n` +
      `    </testcase>`
  );

  const tests = result.findings.length;
  const failures = result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;

  return (
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<testsuite name="vibe-security" tests="${tests}" failures="${failures}" errors="0" time="${(result.durationMs / 1000).toFixed(3)}">\n` +
    cases.join('\n') +
    `\n</testsuite>\n`
  );
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function toCompactMarkdown(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`# Vibe Security Summary`);
  lines.push('');
  lines.push(`- **Total:** ${result.summary.totalFindings}`);
  lines.push(`- **Critical:** ${result.summary.bySeverity.critical}`);
  lines.push(`- **High:** ${result.summary.bySeverity.high}`);
  lines.push(`- **Medium:** ${result.summary.bySeverity.medium}`);
  lines.push('');
  lines.push('| Severity | Rule | File |');
  lines.push('| --- | --- | --- |');
  for (const f of result.findings.slice(0, 50)) {
    lines.push(`| ${f.severity} | \`${f.ruleId}\` | \`${f.file}:${f.match.line}\` |`);
  }
  if (result.findings.length > 50) {
    lines.push(`| _...and ${result.findings.length - 50} more_ | | |`);
  }
  return lines.join('\n');
}

export function formatOutput(format: string, result: ScanResult): string {
  switch (format) {
    case 'sarif':
      return JSON.stringify(toSarif(result), null, 2);
    case 'json':
      return toJson(result);
    case 'junit':
      return toJunit(result);
    case 'compact':
      return toCompactMarkdown(result);
    case 'markdown':
    default:
      return '';
  }
}
