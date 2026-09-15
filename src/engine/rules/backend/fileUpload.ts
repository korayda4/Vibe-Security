import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-007',
  title: 'Unsafe file upload (extension not validated, original filename used)',
  layer: 'backend',
  severity: 'high',
  description:
    'Dosya yuklemesinde sadece `Content-Type` veya extension kontrol edilip sunucuda orijinal isimle saklanirsa, saldirgan `.php`, `.jsp`, `.aspx` veya web-accessible dizine script yukleyebilir (RCE).',
  threat: 'Remote code execution, XSS via SVG, web-shell upload',
  remediation:
    '1) **Magic bytes** ile gercek MIME tespit edin (`file-type` paketi, `python-magic`, vb.). ' +
    '2) Sadece izinli extension + MIME whitelist kabul edin (jpg, png, pdf, vb.). ' +
    '3) Dosyayi **UUID** ile yeniden adlandirin (orijinal ismi KULLANMAYIN). ' +
    '4) Sunucudan BAGIMSIZ depolama kullanin (S3, GCS, R2). Web root\'a yazmayin. ' +
    '5) Boyut limiti koyun (multipart maxFileSize). ' +
    '6) Antivirus / ClamAV ile tarayin. ' +
    '7) Content-Disposition: attachment ile zorla indirme sunun. ' +
    '8) SVG ve HTML\'i reddedin (XSS vektoru).',
  references: [
    'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload',
    'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
  ],
  cwe: 'CWE-434',
  owasp: 'A04:2021 Insecure Design',
  languages: ['javascript', 'typescript', 'python', 'java', 'go'],
  check: (ctx) => {
    const patterns: RegExp[] = [
/diskStorage\s*\([^)]*destination\s*:/g,
      /filename\s*:\s*\(?\s*req\.file\.originalname/g,
/file\.save\s*\(\s*[^)]*originalname/gi,
/transferTo\s*\(\s*new\s+File\s*\(/g,
/filepath\.Join\s*\([^,]*Header\.Filename/g,
    ];

    const findings = [];
    for (const re of patterns) {
      findings.push(...grepRule(rule, ctx, re));
    }
    return findings;
  },
};

export default rule;
