/**
 * Vibe Security smoke tests.
 *
 * Node native test runner ile calistirilir: `npm test`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scan } from '../src/engine/scanner.js';
import { renderSecurityMarkdown } from '../src/engine/reporter.js';
import { getAllRules, getRuleById, getRulesForLanguage } from '../src/engine/rules/index.js';
import { toSarif, toJunit, toCompactMarkdown, formatOutput } from '../src/engine/output.js';
import { applyFixes, applyPatch } from '../src/engine/fixer.js';
import { findingFingerprint, diffAgainstBaseline, writeBaseline, readBaseline } from '../src/engine/baseline.js';
import { detectLanguage, buildProjectProfile } from '../src/engine/language.js';
import { redactSensitiveValues } from '../src/engine/rules/_helpers.js';
import fs from 'node:fs/promises';
import path from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURE_DIR = path.resolve(__dirname, 'fixtures/vulnerable-app');

test('rule registry loads all rules', () => {
  const rules = getAllRules();
  assert.ok(rules.length >= 35, `expected >= 35 rules, got ${rules.length}`);

  const ids = new Set(rules.map((r) => r.id));
  for (const id of ['FE-001', 'FE-003', 'BE-002', 'BE-003', 'BE-004', 'CI-002', 'BE-008', 'BE-009', 'RS-002', 'RB-001', 'PHP-001', 'KT-001']) {
    assert.ok(ids.has(id), `missing critical rule ${id}`);
  }
});

test('rules are categorized by language', () => {
  const jsRules = getRulesForLanguage('javascript');
  const pyRules = getRulesForLanguage('python');
  const goRules = getRulesForLanguage('go');
  const rustRules = getRulesForLanguage('rust');
  const rubyRules = getRulesForLanguage('ruby');
  const phpRules = getRulesForLanguage('php');
  const kotlinRules = getRulesForLanguage('kotlin');

  assert.ok(jsRules.length > 0);
  assert.ok(pyRules.length > 0);
  assert.ok(goRules.length > 0);
  assert.ok(rustRules.length > 0, 'should have Rust rules');
  assert.ok(rubyRules.length > 0, 'should have Ruby rules');
  assert.ok(phpRules.length > 0, 'should have PHP rules');
  assert.ok(kotlinRules.length > 0, 'should have Kotlin rules');
});

test('language detector: extension + shebang + syntax', () => {
  assert.equal(detectLanguage('foo.ts'), 'typescript');
  assert.equal(detectLanguage('foo.rs'), 'rust');
  assert.equal(detectLanguage('foo.rb'), 'ruby');
  assert.equal(detectLanguage('foo.kt'), 'kotlin');

  const pythonShebang = detectLanguage('script', '#!/usr/bin/env python3\nprint("hi")\n');
  assert.equal(pythonShebang, 'python');

  const rubyShebang = detectLanguage('script', '#!/usr/bin/env ruby\nputs "hi"\n');
  assert.equal(rubyShebang, 'ruby');

  const contentSniff = detectLanguage('mystery', 'def foo():\n    pass\n');
  assert.equal(contentSniff, 'python');

  const rustSniff = detectLanguage('mystery', 'fn main() {\n    let x = 1;\n}\n');
  assert.equal(rustSniff, 'rust');
});

test('project profile: primary language and applicable rules', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  assert.ok(result.profile, 'should include project profile');
  assert.ok(
    ['typescript', 'javascript', 'go', 'python', 'json', 'ruby', 'php', 'kotlin', 'rust', 'dockerfile'].includes(
      result.profile!.primary
    ),
    `unexpected primary: ${result.profile!.primary}`
  );
  assert.ok(result.profile!.detected.length > 0);
  assert.ok(result.profile!.applicableRules.length > 0);

  const all = getAllRules().map((r) => r.id);
  for (const ruleId of result.profile!.applicableRules) {
    assert.ok(all.includes(ruleId), `${ruleId} should exist`);
  }
});

test('framework detection: React, Next.js, Vue, Angular, Express, Django, Laravel, .NET', async () => {
  const { detectFrameworks } = await import('../src/engine/language.js');
  const frameworks = await detectFrameworks(FIXTURE_DIR);
  const names = frameworks.map((f) => f.name);

  assert.ok(names.includes('react'), 'should detect React');
  assert.ok(names.includes('nextjs'), 'should detect Next.js');
  assert.ok(names.includes('vue'), 'should detect Vue');
  assert.ok(names.includes('angular'), 'should detect Angular');
  assert.ok(names.includes('express'), 'should detect Express');
  assert.ok(names.includes('django'), 'should detect Django');
  assert.ok(names.includes('laravel'), 'should detect Laravel');
  assert.ok(names.includes('dotnet'), 'should detect .NET');

  for (const fw of frameworks) {
    assert.ok(['frontend', 'backend', 'fullstack', 'build'].includes(fw.category));
    assert.ok(fw.evidence.length > 0);
  }
});

test('getRuleById returns rule details', () => {
  const rule = getRuleById('FE-001');
  assert.ok(rule, 'FE-001 should exist');
  assert.equal(rule.layer, 'frontend');
  assert.equal(rule.severity, 'high');
  assert.ok(rule.remediation.length > 0);
});

test('scan_project finds vulnerabilities in fixture', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });

  assert.ok(result.filesScanned > 0, 'should scan some files');
  assert.ok(result.findings.length > 0, 'should find at least one vulnerability');

  // Check specific rules fired
  const ruleIds = new Set(result.findings.map((f) => f.ruleId));

  // XSS
  assert.ok(ruleIds.has('FE-001'), 'should detect XSS in app.tsx');
  // JWT alg: none
  assert.ok(ruleIds.has('BE-003'), 'should detect JWT alg: none');
  // SQL injection
  assert.ok(ruleIds.has('BE-004'), 'should detect SQL injection');
  // Hardcoded secrets in .env
  assert.ok(ruleIds.has('CI-002'), 'should detect hardcoded secrets');
  // Weak hashing
  assert.ok(ruleIds.has('BE-002'), 'should detect weak hashing');
  // IDOR
  assert.ok(ruleIds.has('BE-001'), 'should detect IDOR');
  // mass assignment
  assert.ok(ruleIds.has('BE-005'), 'should detect mass assignment');
  // Dockerfile
  assert.ok(ruleIds.has('CI-003'), 'should detect Dockerfile issues');
  // source maps
  assert.ok(ruleIds.has('FE-004'), 'should detect production source maps');
  // CORS wildcard
  assert.ok(ruleIds.has('NET-002'), 'should detect CORS wildcard');
  // Logging
  assert.ok(ruleIds.has('OBS-001'), 'should detect stack trace in response');

  // Token safety -- yeni kurallar
  assert.ok(ruleIds.has('BE-008'), 'should detect token in URL');
  assert.ok(ruleIds.has('BE-009'), 'should detect long-lived token');

  // Multi-language: Python f-string SQL should be caught
  const pyFindings = result.findings.filter((f) => f.file.endsWith('.py'));
  assert.ok(pyFindings.length > 0, 'should find Python vulnerabilities');

  // Go: SQL injection + jwt
  const goFindings = result.findings.filter((f) => f.file.endsWith('.go'));
  assert.ok(goFindings.length > 0, 'should find Go vulnerabilities');
});

test('Security.md rendering is structured', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const md = renderSecurityMarkdown(result);

  assert.ok(md.includes('# Security Audit'), 'should have main heading');
  assert.ok(md.includes('## Executive Summary'), 'should have executive summary');
  assert.ok(md.includes('## Findings by Layer'), 'should have layer breakdown');
  assert.ok(md.includes('Generated by [Vibe Security]'), 'should have footer');

  // No findings case shouldn't crash
  const empty = renderSecurityMarkdown({
    ...result,
    findings: [],
    summary: {
      totalFindings: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byLayer: { frontend: 0, backend: 0, network: 0, database: 0, cicd: 0, observability: 0 },
    },
  });
  assert.ok(empty.includes('No security issues detected'));
});

test('layer filtering works', async () => {
  const frontendOnly = await scan({
    rootDir: FIXTURE_DIR,
    layers: ['frontend'],
  });
  assert.ok(
    frontendOnly.findings.every((f) => f.layer === 'frontend'),
    'all findings should be frontend when filtered'
  );

  const cicdOnly = await scan({
    rootDir: FIXTURE_DIR,
    layers: ['cicd'],
  });
  assert.ok(
    cicdOnly.findings.every((f) => f.layer === 'cicd'),
    'all findings should be cicd when filtered'
  );
  assert.ok(
    cicdOnly.findings.some((f) => f.ruleId === 'CI-002'),
    'CI-002 should fire when scanning cicd layer'
  );
});

test('rule id filtering works', async () => {
  const onlySql = await scan({
    rootDir: FIXTURE_DIR,
    ruleIds: ['BE-004'],
  });
  assert.ok(onlySql.findings.length > 0, 'should find SQL injection');
  assert.ok(
    onlySql.findings.every((f) => f.ruleId === 'BE-004'),
    'should only have BE-004 findings'
  );
});

test('language filtering limits scanned findings', async () => {
  const pythonOnly = await scan({ rootDir: FIXTURE_DIR, languages: ['python'] });
  assert.ok(pythonOnly.findings.length > 0, 'should find Python vulnerabilities');
  assert.ok(
    pythonOnly.findings.every(
      (finding) => finding.file.endsWith('.py') || finding.file.endsWith('deploy.sh')
    ),
    'language filter should exclude findings from other files'
  );
});

test('finding snippets redact token-shaped values', () => {
  const snippet = redactSensitiveValues(
    'const token = "super-secret-value";\nAuthorization: Bearer abcdefghijklmnop'
  );
  assert.ok(!snippet.includes('super-secret-value'));
  assert.ok(!snippet.includes('abcdefghijklmnop'));
  assert.ok(snippet.includes('[REDACTED]'));
});

test('SARIF output is valid', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const sarif = toSarif(result) as any;

  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs.length > 0);
  assert.equal(sarif.runs[0].tool.driver.name, 'Vibe Security');
  assert.ok(sarif.runs[0].results.length > 0);

  const firstResult = sarif.runs[0].results[0];
  assert.ok(firstResult.ruleId, 'should have ruleId');
  assert.ok(['error', 'warning', 'note'].includes(firstResult.level));
  assert.ok(firstResult.locations[0].physicalLocation.artifactLocation.uri);
});

test('JUnit output is valid XML', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const xml = toJunit(result);
  assert.ok(xml.startsWith('<?xml version="1.0"'));
  assert.ok(xml.includes('<testsuite'));
  assert.ok(xml.includes('<testcase'));
});

test('Compact markdown is concise', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const md = toCompactMarkdown(result);
  assert.ok(md.includes('# Vibe Security Summary'));
  assert.ok(md.length < result.findings.length * 200);
});

test('Auto-fix: dry-run shows diff without writing', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const summary = await applyFixes(result, { dryRun: true });

  // En azindan FE-004 (source maps) ve NET-002 (CORS) icin fix var
  const fixableRules = new Set(summary.applied.map((f) => f.ruleId));
  assert.ok(fixableRules.size > 0, 'should have at least some auto-fixable findings');

  // Source maps fixture dosyasi degismemis olmali (dry-run)
  const fixture = path.join(FIXTURE_DIR, 'next.config.js');
  const content = await fs.readFile(fixture, 'utf8');
  assert.ok(
    content.includes('productionBrowserSourceMaps: true'),
    'dry-run should not modify file'
  );
});

test('Auto-fix: actually applies patches with --fix', async () => {
  const fixtureFile = path.join(FIXTURE_DIR, 'next.config.js');
  const original = await fs.readFile(fixtureFile, 'utf8');

  try {
    const result = await scan({ rootDir: FIXTURE_DIR });
    await applyFixes(result, { dryRun: false, onlyRuleIds: ['FE-004'] });

    const after = await fs.readFile(fixtureFile, 'utf8');
    assert.ok(
      after.includes('productionBrowserSourceMaps: false'),
      'fix should have changed source maps to false'
    );
    assert.ok(
      !after.includes('productionBrowserSourceMaps: true'),
      'old value should be gone'
    );
  } finally {
    // Restore
    await fs.writeFile(fixtureFile, original, 'utf8');
  }
});

test('applyPatch returns null when snippet not found', () => {
  const result = applyPatch('const x = 1;', {
    find: 'const y = 2;',
    replace: 'const y = 3;',
    description: 'test',
  });
  assert.equal(result, null);
});

test('auto-fix preserves multiple fixes in the same file', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const files = [...new Set(result.findings.filter((finding) => finding.fix).map((finding) => finding.file))];
  const originals = new Map(
    await Promise.all(
      files.map(async (file) => [file, await fs.readFile(path.join(FIXTURE_DIR, file), 'utf8')] as const)
    )
  );
  try {
    const findings = result.findings.filter((finding) => finding.file === 'next.config.js' && finding.fix);
    assert.ok(findings.length > 0, 'fixture should contain fixable findings');
    const summary = await applyFixes(result, { dryRun: false });
    assert.ok(summary.applied.length >= findings.length);
  } finally {
    await Promise.all(
      [...originals].map(([file, content]) => fs.writeFile(path.join(FIXTURE_DIR, file), content, 'utf8'))
    );
  }
});

test('auto-fix skips files outside the scan root', async () => {
  const result = await scan({ rootDir: FIXTURE_DIR });
  const finding = result.findings.find((item) => item.fix);
  assert.ok(finding, 'fixture should contain a fixable finding');
  const summary = await applyFixes(
    { ...result, findings: [{ ...finding, file: '../outside.txt' }] },
    { dryRun: false }
  );
  assert.equal(summary.applied.length, 0);
  assert.equal(summary.skipped[0]?.reason, 'file is outside scan root');
});

test('Baseline: detect new findings on second scan', async () => {
  const baselinePath = path.join(FIXTURE_DIR, '.test-baseline.json');
  const first = await scan({ rootDir: FIXTURE_DIR });
  await writeBaseline(baselinePath, first);

  // Yeni bir bulgu ekleyelim (fixture icine)
  const targetFile = path.join(FIXTURE_DIR, 'src/app.tsx');
  const original = await fs.readFile(targetFile, 'utf8');
  const modified = original + '\n// XSS test\neval("malicious");\n';

  try {
    await fs.writeFile(targetFile, modified, 'utf8');
    const second = await scan({ rootDir: FIXTURE_DIR });
    const baseline = await readBaseline(baselinePath);
    const diff = diffAgainstBaseline(second, baseline);

    assert.ok(diff.newFindings.length > 0, 'should detect new finding');
    assert.ok(
      diff.newFindings.some((f) => f.ruleId === 'FE-006'),
      'should detect the new eval() finding'
    );

    // Eski bulgular resolved olmamali (hÃ¢lÃ¢ orada)
    assert.equal(diff.resolvedFindings.length, 0);
  } finally {
    await fs.writeFile(targetFile, original, 'utf8');
    await fs.unlink(baselinePath).catch(() => {});
  }
});

test('findingFingerprint is stable across re-scans', async () => {
  const r1 = await scan({ rootDir: FIXTURE_DIR });
  const r2 = await scan({ rootDir: FIXTURE_DIR });

  const f1 = r1.findings[0];
  const f2 = r2.findings.find(
    (f) => f.ruleId === f1.ruleId && f.file === f1.file && f.match.line === f1.match.line
  );

  if (f2) {
    assert.equal(findingFingerprint(f1), findingFingerprint(f2));
  }
});

test('config: rule disable via .vibe-security.json', async () => {
  const configPath = path.join(FIXTURE_DIR, '.vibe-security.json');
  let original: string | null = null;
  try {
    original = await fs.readFile(configPath, 'utf8');
  } catch {
    original = null;
  }

  try {
    // CI-002'yi kapat, .env taranmasin
    await fs.writeFile(
      configPath,
      JSON.stringify({ rules: { 'CI-002': { enabled: false } } }),
      'utf8'
    );

    const result = await scan({ rootDir: FIXTURE_DIR });
    const hasCi002 = result.findings.some((f) => f.ruleId === 'CI-002');
    assert.ok(!hasCi002, 'CI-002 should be disabled');
  } finally {
    if (original) {
      await fs.writeFile(configPath, original, 'utf8');
    } else {
      await fs.unlink(configPath).catch(() => {});
    }
  }
});
