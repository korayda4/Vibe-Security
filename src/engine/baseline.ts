import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import type { Finding, ScanResult } from '../types.js';

const BASELINE_VERSION = 1;

export interface BaselineFile {
  readonly version: number;
  readonly createdAt: string;
  readonly findings: readonly BaselineEntry[];
}

export interface BaselineEntry {
  readonly ruleId: string;
  readonly file: string;
  readonly line: number;
  readonly hash: string;
}

export function findingFingerprint(f: Finding): string {
  return createHash('sha256')
    .update(`${f.ruleId}|${f.file}|${f.match.line}|${f.match.snippet.trim()}`)
    .digest('hex')
    .slice(0, 16);
}

export async function readBaseline(filePath: string): Promise<BaselineFile | null> {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw) as BaselineFile;
    if (parsed.version !== BASELINE_VERSION) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function writeBaseline(filePath: string, result: ScanResult): Promise<void> {
  const entries: BaselineEntry[] = result.findings.map((f) => ({
    ruleId: f.ruleId,
    file: f.file,
    line: f.match.line,
    hash: findingFingerprint(f),
  }));

  const file: BaselineFile = {
    version: BASELINE_VERSION,
    createdAt: new Date().toISOString(),
    findings: entries,
  };

  await fs.mkdir(path.dirname(path.resolve(filePath)), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(file, null, 2), 'utf8');
}

export function diffAgainstBaseline(
  result: ScanResult,
  baseline: BaselineFile | null
): { newFindings: readonly Finding[]; resolvedFindings: readonly BaselineEntry[] } {
  if (!baseline) {
    return { newFindings: result.findings, resolvedFindings: [] };
  }

  const currentHashes = new Set(result.findings.map(findingFingerprint));
  const baselineHashes = new Set(baseline.findings.map((e) => e.hash));

  const newFindings = result.findings.filter((f) => !baselineHashes.has(findingFingerprint(f)));
  const resolvedFindings = baseline.findings.filter((e) => !currentHashes.has(e.hash));

  return { newFindings, resolvedFindings };
}
