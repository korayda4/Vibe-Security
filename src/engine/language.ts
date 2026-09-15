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

  return { primary, detected, fileCounts };
}
