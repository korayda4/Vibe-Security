export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Layer =
  | 'frontend'
  | 'backend'
  | 'network'
  | 'database'
  | 'cicd'
  | 'observability'
  | 'lint';

export type Language =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'java'
  | 'kotlin'
  | 'go'
  | 'rust'
  | 'ruby'
  | 'php'
  | 'json'
  | 'yaml'
  | 'toml'
  | 'dockerfile'
  | 'unknown';

export interface MatchContext {
  readonly snippet: string;
  readonly line: number;
  readonly column: number;
}

export interface FixPatch {
  readonly find: string;
  readonly replace: string;
  readonly description: string;
}

export interface Finding {
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly layer: Layer;
  readonly severity: Severity;
  readonly file: string;
  readonly match: MatchContext;
  readonly description: string;
  readonly impact: string;
  readonly remediation: string;
  readonly references: readonly string[];
  readonly cwe?: string;
  readonly owasp?: string;
  readonly fix?: FixPatch;
}

export type RuleCheck = (context: RuleContext) => readonly Finding[];

export interface RuleContext {
  readonly filePath: string;
  readonly relativePath: string;
  readonly language: Language;
  readonly source: string;
  readonly lines: readonly string[];
}

export interface Rule {
  readonly id: string;
  readonly title: string;
  readonly layer: Layer;
  readonly severity: Severity;
  readonly description: string;
  readonly threat: string;
  readonly remediation: string;
  readonly references: readonly string[];
  readonly cwe?: string;
  readonly owasp?: string;
  readonly languages: readonly Language[];
  readonly check: RuleCheck;
}

export interface ScanOptions {
  readonly rootDir?: string;
  readonly targetPath?: string;
  readonly detailed?: boolean;
  readonly layers?: readonly Layer[];
  readonly languages?: readonly Language[];
  readonly dryRun?: boolean;
  readonly reportPath?: string;
  readonly maxMatchesPerFile?: number;
  readonly ignore?: readonly string[];
  readonly ruleIds?: readonly string[];
}

export interface ScanResult {
  readonly rootDir: string;
  readonly targetPath?: string;
  readonly detailed?: boolean;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly durationMs: number;
  readonly filesScanned: number;
  readonly rulesEvaluated: number;
  readonly findings: readonly Finding[];
  readonly summary: ScanSummary;
  readonly errors?: readonly ScanError[];
  readonly reportPath?: string;
  readonly profile?: ProjectProfile;
}

export interface ScanError {
  readonly file?: string;
  readonly ruleId?: string;
  readonly message: string;
}

export interface ProjectProfile {
  readonly primary: Language;
  readonly detected: readonly Language[];
  readonly fileCounts: Readonly<Record<Language, number>>;
  readonly applicableRules: readonly string[];
  readonly frameworks?: readonly FrameworkDetection[];
}

export type Framework =
  | 'react'
  | 'nextjs'
  | 'vue'
  | 'angular'
  | 'svelte'
  | 'express'
  | 'fastify'
  | 'nestjs'
  | 'django'
  | 'flask'
  | 'fastapi'
  | 'rails'
  | 'sinatra'
  | 'laravel'
  | 'symfony'
  | 'wordpress'
  | 'spring'
  | 'dotnet'
  | 'aspnet'
  | 'blazor'
  | 'cpp'
  | 'cmake'
  | 'cplusplus'
  | 'actix'
  | 'axum'
  | 'gin'
  | 'fiber';

export interface FrameworkDetection {
  readonly name: Framework;
  readonly category: 'frontend' | 'backend' | 'fullstack' | 'build';
  readonly version?: string;
  readonly evidence: readonly string[];
}

export interface ScanSummary {
  readonly totalFindings: number;
  readonly bySeverity: Record<Severity, number>;
  readonly byLayer: Record<Layer, number>;
}

export type BuildVerdict = 'SUCCESS' | 'WARNING' | 'SECURITY_VULNERABILITY';

export interface BuildCheckOptions extends ScanOptions {
  readonly blockSeverities?: readonly Severity[];
  readonly writeReport?: boolean;
  readonly reportPath?: string;
  readonly fix?: boolean;
  readonly autoPatch?: boolean;
  readonly dryRun?: boolean;
}

export interface BuildCheckResult {
  readonly verdict: BuildVerdict;
  readonly exitCode: number;
  readonly scanResult: ScanResult;
  readonly summary: ScanSummary;
  readonly criticalCount: number;
  readonly highCount: number;
  readonly warningCount: number;
  readonly blockingFindings: readonly Finding[];
  readonly warningFindings: readonly Finding[];
  readonly reportPath?: string;
  readonly terminalOutput: string;
  readonly appliedFixes?: readonly { readonly file: string; readonly ruleId: string; readonly description: string }[];
  readonly fixSummary?: string;
}

