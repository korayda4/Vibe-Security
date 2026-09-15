import type { Rule } from '../../../types.js';
import { grepRule } from '../_helpers.js';

const rule: Rule = {
  id: 'BE-007',
  title: 'Unsafe file upload (extension not validated, original filename used)',
  layer: 'backend',
  severity: 'high',
  description:
    'If file uploads only validate `Content-Type` or extension and then store the file on the server under its original name, an attacker can upload `.php`, `.jsp`, `.aspx`, or any web-accessible script (RCE).',
  threat: 'Remote code execution, XSS via SVG, web-shell upload',
  remediation:
    '1) Detect the real MIME via **magic bytes** (e.g. `file-type` package, `python-magic`). ' +
    '2) Allow only an explicit extension + MIME whitelist (jpg, png, pdf, etc.). ' +
    '3) Rename the file with a **UUID** (do NOT keep the original name). ' +
    '4) Store OUTSIDE the web root (S3, GCS, R2). Never write to a publicly served directory. ' +
    '5) Enforce a size limit (multipart maxFileSize). ' +
    '6) Scan with antivirus / ClamAV. ' +
    '7) Force `Content-Disposition: attachment` for downloads. ' +
    '8) Reject SVG and HTML (XSS vectors).',
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
