import fs from 'node:fs/promises';
import path from 'node:path';
import type { Finding, FixPatch, ScanResult } from '../types.js';

export interface AppliedFix {
  readonly file: string;
  readonly ruleId: string;
  readonly description: string;
  readonly before: string;
  readonly after: string;
}

export interface FixSummary {
  readonly applied: readonly AppliedFix[];
  readonly skipped: readonly { ruleId: string; file: string; reason: string }[];
}

export function applyPatch(source: string, patch: FixPatch): string | null {
  if (!source.includes(patch.find)) return null;
  return source.replace(patch.find, patch.replace);
}

export async function applyFixes(
  result: ScanResult,
  options: { dryRun: boolean; onlyRuleIds?: readonly string[] }
): Promise<FixSummary> {
  const fixesByFile = new Map<string, AppliedFix[]>();
  const skipped: { ruleId: string; file: string; reason: string }[] = [];
  const findingsByFile = new Map<string, Finding[]>();

  for (const finding of result.findings) {
    if (!finding.fix) continue;
    if (options.onlyRuleIds && !options.onlyRuleIds.includes(finding.ruleId)) continue;
    const list = findingsByFile.get(finding.file) ?? [];
    list.push(finding);
    findingsByFile.set(finding.file, list);
  }

  const rootDir = await fs.realpath(result.rootDir).catch(() => path.resolve(result.rootDir));
  for (const [relativeFile, fileFindings] of findingsByFile) {
    const absPath = path.resolve(result.rootDir, relativeFile);
    const relativeToRoot = path.relative(rootDir, absPath);
    if (relativeToRoot.startsWith('..' + path.sep) || path.isAbsolute(relativeToRoot)) {
      for (const finding of fileFindings) {
        skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'file is outside scan root' });
      }
      continue;
    }

    const realPath = await fs.realpath(absPath).catch(() => null);
    if (!realPath) {
      for (const finding of fileFindings) {
        skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'cannot resolve file' });
      }
      continue;
    }
    const realRelativeToRoot = path.relative(rootDir, realPath);
    if (realRelativeToRoot.startsWith('..' + path.sep) || path.isAbsolute(realRelativeToRoot)) {
      for (const finding of fileFindings) {
        skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'file resolves outside scan root' });
      }
      continue;
    }

    let source: string;
    try {
      source = await fs.readFile(absPath, 'utf8');
    } catch {
      for (const finding of fileFindings) {
        skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'cannot read file' });
      }
      continue;
    }

    let current = source;
    for (const finding of fileFindings) {
      const patched = applyPatch(current, finding.fix!);
      if (patched === null) {
        skipped.push({
          ruleId: finding.ruleId,
          file: finding.file,
          reason: 'patch snippet not found (file may have changed)',
        });
        continue;
      }
      if (patched === current) {
        skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'no change' });
        continue;
      }

      const entry: AppliedFix = {
        file: finding.file,
        ruleId: finding.ruleId,
        description: finding.fix!.description,
        before: finding.fix!.find.trim(),
        after: finding.fix!.replace.trim(),
      };
      const entries = fixesByFile.get(finding.file) ?? [];
      entries.push(entry);
      fixesByFile.set(finding.file, entries);
      current = patched;
    }

    if (!options.dryRun && current !== source) {
      await fs.writeFile(absPath, current, 'utf8');
    }
  }

  const applied: AppliedFix[] = [];
  for (const list of fixesByFile.values()) applied.push(...list);

  return { applied, skipped };
}

export function formatFixSummary(summary: FixSummary, dryRun: boolean): string {
  const out: string[] = [];
  out.push(dryRun ? '## 🔍 Auto-fix Dry Run' : '## ✅ Auto-fix Applied');
  out.push('');

  if (summary.applied.length === 0) {
    out.push('_No auto-fixable findings._');
    return out.join('\n');
  }

  out.push(`${summary.applied.length} fix(es) ${dryRun ? 'would be applied' : 'applied'}:`);
  out.push('');

  for (const fix of summary.applied) {
    out.push(`### [\`${fix.ruleId}\`] ${fix.file}`);
    out.push('');
    out.push(fix.description);
    out.push('');
    out.push('```diff');
    out.push(`- ${fix.before.split('\n')[0]}${fix.before.includes('\n') ? '\n  …' : ''}`);
    out.push(`+ ${fix.after.split('\n')[0]}${fix.after.includes('\n') ? '\n  …' : ''}`);
    out.push('```');
    out.push('');
  }

  if (summary.skipped.length > 0) {
    out.push('### Skipped');
    out.push('');
    for (const s of summary.skipped) {
      out.push(`- [\`${s.ruleId}\`] ${s.file} — ${s.reason}`);
    }
  }

  return out.join('\n');
}
