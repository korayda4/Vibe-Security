import fs from 'node:fs/promises';
import path from 'node:path';

export interface WalkedFile {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly sizeBytes: number;
}

const DEFAULT_IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'coverage',
  '.cache',
  '.turbo',
  '.vercel',
  '.output',
  'out',
  'vendor',
  'target',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  '.venv',
  'venv',
  '.gradle',
  '.idea',
  '.vscode',
  '.DS_Store',
]);

const MAX_FILE_SIZE = 2 * 1024 * 1024;

export interface WalkOptions {
  readonly rootDir: string;
  readonly ignore?: readonly string[];
  readonly maxFiles?: number;
}

export async function walkProject(options: WalkOptions): Promise<readonly WalkedFile[]> {
  const { rootDir } = options;
  const userIgnore = new Set(options.ignore ?? []);
  const maxFiles = options.maxFiles ?? 10_000;

  const results: WalkedFile[] = [];

  async function visit(dir: string): Promise<void> {
    if (results.length >= maxFiles) return;

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (results.length >= maxFiles) return;

      const name = entry.name;
      if (userIgnore.has(name) || userIgnore.has(`**/${name}`) || userIgnore.has(`**/${name}/**`)) {
        continue;
      }

      const full = path.join(dir, name);
      const rel = path.relative(rootDir, full);

      if (entry.isDirectory()) {
        if (
          DEFAULT_IGNORED_DIRS.has(name) ||
          (name.startsWith('.') &&
            name !== '.env' &&
            name !== '.env.example' &&
            name !== '.gitignore')
        ) {
          continue;
        }
        await visit(full);
        continue;
      }

      if (!entry.isFile()) continue;

      if (name.startsWith('.')) {
        const allowed =
          name === '.env' || name === '.env.example' || name === '.gitignore' || name === '.dockerignore';
        if (!allowed) continue;
      }

      let stat;
      try {
        stat = await fs.stat(full);
      } catch {
        continue;
      }

      if (stat.size > MAX_FILE_SIZE) continue;

      results.push({
        absolutePath: full,
        relativePath: rel.split(path.sep).join('/'),
        sizeBytes: stat.size,
      });
    }
  }

  await visit(rootDir);
  return results;
}
