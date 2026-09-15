import type { Finding, FixPatch, Rule, RuleContext } from '../../types.js';

export function* matchAll(re: RegExp, source: string): Generator<RegExpExecArray> {
  if (re.global || re.sticky) {
    const matches = source.matchAll(re);
    for (const m of matches) yield m;
    return;
  }
  const m = re.exec(source);
  if (m) yield m;
}

export function lineColumnFromIndex(source: string, index: number): { line: number; column: number } {
  let line = 1;
  let col = 0;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === '\n') {
      line++;
      col = 0;
    } else {
      col++;
    }
  }
  return { line, column: col };
}

export function snippetAt(source: string, line: number, contextLines = 1): string {
  const lines = source.split(/\r?\n/);
  const start = Math.max(0, line - 1 - contextLines);
  const end = Math.min(lines.length, line + contextLines);
  return lines.slice(start, end).join('\n');
}

export function makeFinding(
  rule: Rule,
  ctx: RuleContext,
  matchIndex: number,
  matchLength: number,
  fix?: FixPatch
): Finding {
  const { line, column } = lineColumnFromIndex(ctx.source, matchIndex);
  return {
    id: `${rule.id}-${ctx.relativePath}-${line}-${column}`,
    ruleId: rule.id,
    title: rule.title,
    layer: rule.layer,
    severity: rule.severity,
    file: ctx.relativePath,
    match: {
      snippet: snippetAt(ctx.source, line),
      line,
      column,
    },
    description: rule.description,
    impact: rule.threat,
    remediation: rule.remediation,
    references: rule.references,
    cwe: rule.cwe,
    owasp: rule.owasp,
    fix,
  };
}

export function grepRule(rule: Rule, ctx: RuleContext, re: RegExp): Finding[] {
  const out: Finding[] = [];
  for (const m of matchAll(re, ctx.source)) {
    if (m.index === undefined) continue;
    out.push(makeFinding(rule, ctx, m.index, m[0].length));
  }
  return out;
}
