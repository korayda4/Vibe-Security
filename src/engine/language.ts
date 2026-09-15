import path from 'node:path';
import type { Language } from '../types.js';

const EXTENSION_MAP: Record<string, Language> = {
  '.js': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.tsx': 'typescript',
  '.py': 'python',
  '.pyi': 'python',
  '.java': 'java',
  '.go': 'go',
  '.json': 'json',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.toml': 'toml',
  '.lock': 'json',
};

const FILENAME_MAP: Record<string, Language> = {
  Dockerfile: 'dockerfile',
  Containerfile: 'dockerfile',
  Makefile: 'unknown',
};

export const DATABASE_PATH_HINTS = [
  'prisma',
  'migrations',
  'db',
  'database',
  'sql',
  'drizzle',
  'knex',
  'sequelize',
];

export const CONFIG_PATH_HINTS = [
  'next.config',
  'vite.config',
  'webpack.config',
  '.eslintrc',
  '.env',
  'docker-compose',
  'tsconfig',
  'package.json',
];

export function detectLanguage(filePath: string): Language {
  const base = path.basename(filePath);
  if (FILENAME_MAP[base]) {
    return FILENAME_MAP[base];
  }
  const ext = path.extname(base).toLowerCase();
  return EXTENSION_MAP[ext] ?? 'unknown';
}

export function isCodeLanguage(lang: Language): boolean {
  return (
    lang === 'javascript' ||
    lang === 'typescript' ||
    lang === 'python' ||
    lang === 'java' ||
    lang === 'go'
  );
}

export function isConfigLanguage(lang: Language): boolean {
  return (
    lang === 'json' ||
    lang === 'yaml' ||
    lang === 'toml' ||
    lang === 'dockerfile' ||
    lang === 'unknown'
  );
}
