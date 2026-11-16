import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

export const NAME = pkg.name;
export const VERSION = pkg.version;
// "git+https://github.com/<owner>/<repo>.git" -> "https://github.com/<owner>/<repo>"
export const REPO_URL = String(pkg.repository?.url || '').replace(/^git\+/, '').replace(/\.git$/, '');
