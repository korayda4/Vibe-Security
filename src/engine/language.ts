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
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.go': 'go',
  '.rs': 'rust',
  '.rb': 'ruby',
  '.php': 'php',
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
  Gemfile: 'ruby',
  Rakefile: 'ruby',
};

const SHEBANG_MAP: Record<string, Language> = {
  python: 'python',
  python3: 'python',
  ruby: 'ruby',
  node: 'javascript',
  nodejs: 'javascript',
  deno: 'typescript',
  bun: 'typescript',
  php: 'php',
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

export function detectByExtension(filePath: string): Language | null {
  const base = path.basename(filePath);
  if (FILENAME_MAP[base]) {
    return FILENAME_MAP[base];
  }
  if (base === '.env' || base.startsWith('.env.')) {
    return 'unknown';
  }
  const ext = path.extname(base).toLowerCase();
  return EXTENSION_MAP[ext] ?? null;
}

export function detectByShebang(source: string): Language | null {
  const firstLine = source.split('\n', 1)[0] ?? '';
  const match = firstLine.match(/^#!\s*\/(?:usr\/bin\/env\s+)?(\w+)/);
  if (!match) return null;
  const interpreter = match[1].toLowerCase();
  return SHEBANG_MAP[interpreter] ?? null;
}

const SYNTAX_HINTS: Array<{ language: Language; pattern: RegExp }> = [
  { language: 'python', pattern: /^\s*(def |class |import |from .+ import |@\w+|if __name__ == ['"]__main__['"]:)/m },
  { language: 'ruby', pattern: /^\s*(def |class |module |require ['"]|Rails\.application|attr_accessor|do\s*\|)/m },
  { language: 'go', pattern: /^\s*(package |func |import \(|type \w+ struct)/m },
  { language: 'rust', pattern: /^\s*(fn |impl |use |pub fn |let mut |struct |enum |#\[derive|#\[tokio::)/m },
  { language: 'java', pattern: /^\s*(public class |private class |package |import java\.|@Override|@Autowired)/m },
  { language: 'kotlin', pattern: /^\s*(fun |class |val |var |import kotlin|@Composable|@SpringBootApplication)/m },
  { language: 'php', pattern: /^\s*(<\?php|namespace |use \w+\\\w+;|public function |private function )/m },
  { language: 'typescript', pattern: /^\s*(import type |export type |interface \w+ \{|:\s*(string|number|boolean)\b)/m },
  { language: 'javascript', pattern: /^\s*(const |let |function |require\(|module\.exports|=>\s*\{)/m },
];

export function detectBySyntax(source: string): Language | null {
  for (const hint of SYNTAX_HINTS) {
    if (hint.pattern.test(source)) {
      return hint.language;
    }
  }
  return null;
}

export function detectLanguage(filePath: string, source?: string): Language {
  const byExt = detectByExtension(filePath);
  if (byExt) return byExt;
  if (source) {
    const byShebang = detectByShebang(source);
    if (byShebang) return byShebang;
    const bySyntax = detectBySyntax(source);
    if (bySyntax) return bySyntax;
  }
  return 'unknown';
}

export function isCodeLanguage(lang: Language): boolean {
  return (
    lang === 'javascript' ||
    lang === 'typescript' ||
    lang === 'python' ||
    lang === 'java' ||
    lang === 'kotlin' ||
    lang === 'go' ||
    lang === 'rust' ||
    lang === 'ruby' ||
    lang === 'php'
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

export interface ProjectProfile {
  readonly primary: Language;
  readonly detected: readonly Language[];
  readonly fileCounts: Readonly<Record<Language, number>>;
  readonly frameworks: readonly FrameworkDetection[];
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

const FRONTEND_PACKAGES: Record<string, Framework> = {
  react: 'react',
  next: 'nextjs',
  nextjs: 'nextjs',
  vue: 'vue',
  '@angular/core': 'angular',
  svelte: 'svelte',
};

const BACKEND_PACKAGES: Record<string, Framework> = {
  express: 'express',
  fastify: 'fastify',
  '@nestjs/core': 'nestjs',
  django: 'django',
  flask: 'flask',
  fastapi: 'fastapi',
  rails: 'rails',
  sinatra: 'sinatra',
  laravel: 'laravel',
  symfony: 'symfony',
  '@springframework': 'spring',
  '@aspnet/core': 'aspnet',
  blazor: 'blazor',
};

export async function detectFrameworks(
  rootDir: string
): Promise<FrameworkDetection[]> {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const detections: FrameworkDetection[] = [];

  async function fileExistsWithExtension(dir: string, ext: string): Promise<boolean> {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      return entries.some((e) => e.isFile() && e.name.toLowerCase().endsWith(ext));
    } catch {
      return false;
    }
  }

  const tryRead = async (rel: string): Promise<string | null> => {
    try {
      return await fs.readFile(path.join(rootDir, rel), 'utf8');
    } catch {
      return null;
    }
  };

  const packageJson = await tryRead('package.json');
  if (packageJson) {
    try {
      const pkg = JSON.parse(packageJson) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      const evidence: string[] = [];
      for (const [name, ver] of Object.entries(allDeps)) {
        const fw = FRONTEND_PACKAGES[name] ?? BACKEND_PACKAGES[name];
        if (!fw) continue;
        evidence.push(`${name}@${ver}`);
        const existing = detections.find((d) => d.name === fw);
        if (!existing) {
          const isFrontend = (Object.values(FRONTEND_PACKAGES) as string[]).includes(fw);
          detections.push({
            name: fw,
            category: isFrontend ? 'frontend' : 'backend',
            version: ver,
            evidence: [`package.json: ${name}@${ver}`],
          });
        }
      }
    } catch {
      // ignore malformed package.json
    }
  }

  const composerJson = await tryRead('composer.json');
  if (composerJson) {
    try {
      const composer = JSON.parse(composerJson) as {
        require?: Record<string, string>;
      };
      for (const [name, ver] of Object.entries(composer.require ?? {})) {
        let fw: Framework | null = null;
        if (name.startsWith('laravel/framework')) fw = 'laravel';
        else if (name.startsWith('symfony/')) fw = 'symfony';
        if (!fw) continue;
        if (!detections.find((d) => d.name === fw)) {
          detections.push({
            name: fw,
            category: 'backend',
            version: ver,
            evidence: [`composer.json: ${name}@${ver}`],
          });
        }
      }
    } catch {
      // ignore
    }
  }

  const requirementsTxt = await tryRead('requirements.txt');
  if (requirementsTxt) {
    const pyFrameworks: Array<{ pkg: string; fw: Framework }> = [
      { pkg: 'django', fw: 'django' },
      { pkg: 'flask', fw: 'flask' },
      { pkg: 'fastapi', fw: 'fastapi' },
    ];
    for (const { pkg, fw } of pyFrameworks) {
      const re = new RegExp(`^${pkg}\\s*[>=~]=?\\s*([\\d.]+)`, 'm');
      const m = requirementsTxt.match(re);
      if (m && !detections.find((d) => d.name === fw)) {
        detections.push({
          name: fw,
          category: 'backend',
          version: m[1],
          evidence: [`requirements.txt: ${pkg}==${m[1]}`],
        });
      }
    }
  }

  const pyproject = await tryRead('pyproject.toml');
  if (pyproject) {
    const pyFrameworks: Array<{ pkg: string; fw: Framework }> = [
      { pkg: 'django', fw: 'django' },
      { pkg: 'flask', fw: 'flask' },
      { pkg: 'fastapi', fw: 'fastapi' },
    ];
    for (const { pkg, fw } of pyFrameworks) {
      const re = new RegExp(`${pkg}\\s*[>=~]=?\\s*["']?([\\d.]+)`, 'm');
      const m = pyproject.match(re);
      if (m && !detections.find((d) => d.name === fw)) {
        detections.push({
          name: fw,
          category: 'backend',
          version: m[1],
          evidence: [`pyproject.toml: ${pkg}==${m[1]}`],
        });
      }
    }
  }

  const gemfile = await tryRead('Gemfile');
  if (gemfile) {
    if (/^\s*gem\s+['"]rails['"]/m.test(gemfile) && !detections.find((d) => d.name === 'rails')) {
      detections.push({ name: 'rails', category: 'backend', evidence: ['Gemfile: rails'] });
    }
    if (/^\s*gem\s+['"]sinatra['"]/m.test(gemfile) && !detections.find((d) => d.name === 'sinatra')) {
      detections.push({ name: 'sinatra', category: 'backend', evidence: ['Gemfile: sinatra'] });
    }
  }

  const csprojExists = await fileExistsWithExtension(rootDir, '.csproj');
  const slnExists = await fileExistsWithExtension(rootDir, '.sln');
  if (csprojExists || slnExists) {
    if (!detections.find((d) => d.name === 'dotnet')) {
      detections.push({
        name: 'dotnet',
        category: 'backend',
        evidence: [csprojExists ? '*.csproj found' : '*.sln found'],
      });
    }
  }

  const cppFiles = await fileExistsWithExtension(rootDir, '.cpp');
  if (cppFiles) {
    if (!detections.find((d) => d.name === 'cpp')) {
      detections.push({ name: 'cpp', category: 'backend', evidence: ['*.cpp files found'] });
    }
  }

  const cargoToml = await tryRead('Cargo.toml');
  if (cargoToml && /^\[package\]/m.test(cargoToml)) {
    const actix = /^actix-web\s*=/m.test(cargoToml);
    const axum = /^axum\s*=/m.test(cargoToml);
    if (actix && !detections.find((d) => d.name === 'actix')) {
      detections.push({ name: 'actix', category: 'backend', evidence: ['Cargo.toml: actix-web'] });
    } else if (axum && !detections.find((d) => d.name === 'axum')) {
      detections.push({ name: 'axum', category: 'backend', evidence: ['Cargo.toml: axum'] });
    }
  }

  const goMod = await tryRead('go.mod');
  if (goMod) {
    if (/^\s*github\.com\/gin-gonic\/gin/m.test(goMod) && !detections.find((d) => d.name === 'gin')) {
      detections.push({ name: 'gin', category: 'backend', evidence: ['go.mod: gin-gonic/gin'] });
    }
    if (/^\s*github\.com\/gofiber\/fiber/m.test(goMod) && !detections.find((d) => d.name === 'fiber')) {
      detections.push({ name: 'fiber', category: 'backend', evidence: ['go.mod: gofiber/fiber'] });
    }
  }

  const cmakeLists = await tryRead('CMakeLists.txt');
  if (cmakeLists && !detections.find((d) => d.name === 'cmake')) {
    detections.push({ name: 'cmake', category: 'build', evidence: ['CMakeLists.txt found'] });
  }

  return detections;
}

export function buildProjectProfile(
  files: readonly { relativePath: string; source?: string }[]
): ProjectProfile {
  const counts: Partial<Record<Language, number>> = {};
  for (const f of files) {
    const lang = detectLanguage(f.relativePath, f.source);
    if (lang === 'unknown') continue;
    counts[lang] = (counts[lang] ?? 0) + 1;
  }

  let primary: Language = 'unknown';
  let maxCount = 0;
  for (const [lang, count] of Object.entries(counts)) {
    if (count > maxCount) {
      maxCount = count;
      primary = lang as Language;
    }
  }

  const detected = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([lang]) => lang as Language);

  const fileCounts: Record<Language, number> = {
    javascript: 0,
    typescript: 0,
    python: 0,
    java: 0,
    kotlin: 0,
    go: 0,
    rust: 0,
    ruby: 0,
    php: 0,
    json: 0,
    yaml: 0,
    toml: 0,
    dockerfile: 0,
    unknown: 0,
  };
  for (const [lang, count] of Object.entries(counts)) {
    fileCounts[lang as Language] = count;
  }

  return {
    primary,
    detected,
    fileCounts,
    frameworks: [],
  };
}
