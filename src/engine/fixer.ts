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

  for (const finding of result.findings) {
    if (!finding.fix) continue;
    if (options.onlyRuleIds && !options.onlyRuleIds.includes(finding.ruleId)) continue;

    const absPath = path.resolve(result.rootDir, finding.file);
    let source: string;
    try {
      source = await fs.readFile(absPath, 'utf8');
    } catch {
      skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'cannot read file' });
      continue;
    }

    const patched = applyPatch(source, finding.fix);
    if (patched === null) {
      skipped.push({
        ruleId: finding.ruleId,
        file: finding.file,
        reason: 'patch snippet not found (file may have changed)',
      });
      continue;
    }

    if (patched === source) {
      skipped.push({ ruleId: finding.ruleId, file: finding.file, reason: 'no change' });
      continue;
    }

    const entry: AppliedFix = {
      file: finding.file,
      ruleId: finding.ruleId,
      description: finding.fix.description,
      before: finding.fix.find.trim(),
      after: finding.fix.replace.trim(),
    };

    if (!fixesByFile.has(finding.file)) fixesByFile.set(finding.file, []);
    fixesByFile.get(finding.file)!.push(entry);

    if (!options.dryRun) {
      await fs.writeFile(absPath, patched, 'utf8');
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
