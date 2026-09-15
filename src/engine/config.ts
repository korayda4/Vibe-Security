import fs from 'node:fs/promises';
import path from 'node:path';
import type { Layer, Severity } from '../types.js';

export interface AiSecurityConfig {
  readonly rules?: Record<string, { enabled?: boolean; severity?: Severity }>;
  readonly ignore?: readonly string[];
  readonly output?: {
    readonly format?: 'markdown' | 'json' | 'sarif' | 'junit' | 'compact';
    readonly path?: string;
  };
  readonly baseline?: string;
  readonly autoFix?: boolean;
  readonly layers?: readonly Layer[];
}

const DEFAULT_CONFIG: AiSecurityConfig = {};

export async function loadConfig(rootDir: string): Promise<AiSecurityConfig> {
  const candidates = [
    path.join(rootDir, '.vibe-security.json'),
    path.join(rootDir, '.vibe-securityrc.json'),
  ];

  for (const file of candidates) {
    try {
      const raw = await fs.readFile(file, 'utf8');
      const parsed = JSON.parse(raw) as AiSecurityConfig;
      return mergeConfig(DEFAULT_CONFIG, parsed);
    } catch {
      continue;
    }
  }

  return DEFAULT_CONFIG;
}

export function mergeConfig(base: AiSecurityConfig, override: AiSecurityConfig): AiSecurityConfig {
  return {
    rules: { ...(base.rules ?? {}), ...(override.rules ?? {}) },
    ignore: [...(base.ignore ?? []), ...(override.ignore ?? [])],
    output: { ...(base.output ?? {}), ...(override.output ?? {}) },
    baseline: override.baseline ?? base.baseline,
    autoFix: override.autoFix ?? base.autoFix,
    layers: override.layers ?? base.layers,
  };
}

export function applyConfig(
  config: AiSecurityConfig,
  scanOptions: { layers?: readonly Layer[]; ignore?: readonly string[]; ruleIds?: readonly string[] }
): { layers?: readonly Layer[]; ignore: readonly string[]; ruleIds?: readonly string[] } {
  const disabledRuleIds = Object.entries(config.rules ?? {})
    .filter(([, v]) => v.enabled === false)
    .map(([k]) => k);

  return {
    layers: config.layers ?? scanOptions.layers,
    ignore: [...(scanOptions.ignore ?? []), ...(config.ignore ?? [])],
    ruleIds: [...(scanOptions.ruleIds ?? []), ...disabledRuleIds],
  };
}
