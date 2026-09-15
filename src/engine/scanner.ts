import fs from 'node:fs/promises';
import { detectLanguage } from './language.js';
import { walkProject, type WalkedFile } from './walker.js';
import { getRulesForLanguage, type RegisteredRule } from './rules/index.js';
import type {
  Finding,
  Language,
  Layer,
  ScanOptions,
  ScanResult,
  ScanSummary,
  Severity,
} from '../types.js';
import { loadConfig, applyConfig, type AiSecurityConfig } from './config.js';

const ALL_SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const ALL_LAYERS: readonly Layer[] = ['frontend', 'backend', 'network', 'database', 'cicd', 'observability'];
const GLOBAL_FINDING_CAP = 5000;
const PER_FILE_FINDING_CAP = 50;

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date();
  const rootDir = options.rootDir ?? process.cwd();
  const config = await loadConfig(rootDir);
  const effective = applyConfig(config, {
    layers: options.layers,
    ignore: options.ignore,
    ruleIds: options.ruleIds,
  });

  const layers = (effective.layers && effective.layers.length > 0 ? effective.layers : ALL_LAYERS) as readonly Layer[];
  const disabledRuleIds = new Set(
    Object.entries(config.rules ?? {})
      .filter(([, v]) => v.enabled === false)
      .map(([k]) => k)
  );
  const severityOverrides = new Map<string, Severity>();
  for (const [id, v] of Object.entries(config.rules ?? {})) {
    if (v.severity) severityOverrides.set(id, v.severity);
  }

  const files = await walkProject({
    rootDir,
    ignore: effective.ignore,
  });

  const rulesEvaluated = new Set<string>();
  const findings: Finding[] = [];
  const maxPerFile = options.maxMatchesPerFile ?? PER_FILE_FINDING_CAP;

  for (const file of files) {
    const language = detectLanguage(file.relativePath);
    const candidates = getRulesForLanguage(language);
    const applicable = candidates.filter((r) => {
      if (disabledRuleIds.has(r.id)) return false;
      if (effective.ruleIds && effective.ruleIds.length > 0) {
        if (!effective.ruleIds.includes(r.id)) return false;
      }
      if (!layers.includes(r.layer)) return false;
      return true;
    });

    if (applicable.length === 0) continue;

    let source: string;
    let lines: string[];
    try {
      source = await fs.readFile(file.absolutePath, 'utf8');
    } catch {
      continue;
    }
    lines = source.split(/\r?\n/);

    for (const rule of applicable) {
      rulesEvaluated.add(rule.id);

      let ruleFindings: readonly Finding[];
      try {
        ruleFindings = rule.check({
          filePath: file.absolutePath,
          relativePath: file.relativePath,
          language,
          source,
          lines,
        });
      } catch (err) {
        continue;
      }

      for (let finding of ruleFindings) {
        if (findings.length >= maxPerFile * 100) break;
        const override = severityOverrides.get(finding.ruleId);
        if (override) {
          finding = { ...finding, severity: override };
        }
        findings.push(finding);
      }
    }
  }

  const finishedAt = new Date();
  const summary = summarize(findings);

  return {
    rootDir,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    filesScanned: files.length,
    rulesEvaluated: rulesEvaluated.size,
    findings: findings.slice(0, GLOBAL_FINDING_CAP),
    summary,
  };
}

export function summarize(findings: readonly Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const byLayer: Record<Layer, number> = {
    frontend: 0,
    backend: 0,
    network: 0,
    database: 0,
    cicd: 0,
    observability: 0,
  };
  for (const f of findings) {
    bySeverity[f.severity]++;
    byLayer[f.layer]++;
  }
  return { totalFindings: findings.length, bySeverity, byLayer };
}

export type { WalkedFile, Language };
