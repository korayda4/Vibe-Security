/**
 * Vibe Security - Core Programmatic Library API
 *
 * Exported for use in scripts, CI pipelines, and custom security integrations.
 */

// Scanner engine
export { scan, summarize } from './engine/scanner.js';

// Fixer engine
export { applyFixes, applyPatch, formatFixSummary } from './engine/fixer.js';
export type { AppliedFix, FixSummary } from './engine/fixer.js';

// Reporter & Outputs
export { writeSecurityReport, renderSecurityMarkdown } from './engine/reporter.js';
export { formatOutput, toSarif, toJunit, toCompactMarkdown } from './engine/output.js';

// Rules registry
export {
  getAllRules,
  getRuleById,
  getRulesForLanguage,
  getRulesByLayer,
  getRulesByLanguages,
} from './engine/rules/index.js';
export type { RegisteredRule } from './engine/rules/index.js';

// Language & Framework profiling
export { detectLanguage, detectFrameworks, buildProjectProfile } from './engine/language.js';

// Baseline regression tracking
export {
  readBaseline,
  writeBaseline,
  diffAgainstBaseline,
  findingFingerprint,
} from './engine/baseline.js';
export type { BaselineFile, BaselineEntry } from './engine/baseline.js';

// Configuration
export { loadConfig, applyConfig, mergeConfig } from './engine/config.js';
export type { AiSecurityConfig } from './engine/config.js';

// MCP Server
export { server, startServer } from './server.js';

// Build Guard (Automated Build Gate)
export { checkBuild } from './engine/buildGuard.js';
export type { BuildVerdict, BuildCheckOptions, BuildCheckResult } from './engine/buildGuard.js';

// Type definitions
export * from './types.js';
