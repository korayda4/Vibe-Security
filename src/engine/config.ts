import fs from 'node:fs/promises';
import path from 'node:path';
import type { Language, Layer, Severity } from '../types.js';

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
  readonly languages?: readonly Language[];
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
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw new Error(`Invalid Vibe Security config at ${file}: ${error instanceof Error ? error.message : String(error)}`);
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
    languages: override.languages ?? base.languages,
  };
}

export function applyConfig(
  config: AiSecurityConfig,
  scanOptions: {
    layers?: readonly Layer[];
    languages?: readonly Language[];
    ignore?: readonly string[];
    ruleIds?: readonly string[];
  }
): {
  layers?: readonly Layer[];
  languages?: readonly Language[];
  ignore: readonly string[];
  ruleIds?: readonly string[];
} {
  const disabledRuleIds = Object.entries(config.rules ?? {})
    .filter(([, v]) => v.enabled === false)
    .map(([k]) => k);

  return {
    layers: scanOptions.layers ?? config.layers,
    languages: scanOptions.languages ?? config.languages,
    ignore: [...(scanOptions.ignore ?? []), ...(config.ignore ?? [])],
    ruleIds: [...(scanOptions.ruleIds ?? []), ...disabledRuleIds],
  };
}
