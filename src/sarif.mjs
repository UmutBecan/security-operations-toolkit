import { createHash } from 'node:crypto';
import path from 'node:path';
import { ruleFor } from './rules.mjs';
import { NAME, VERSION, REPO_URL } from './meta.mjs';

// SARIF 2.1.0 for GitHub code scanning. Required fields follow GitHub's "SARIF support for code scanning":
//   sarifLog $schema/version/runs; run.tool.driver.name + rules; rule id + shortDescription + fullDescription + help;
//   result message.text + locations[].physicalLocation (artifactLocation.uri + full region) + partialFingerprints.
// Findings are about domains, not source files, so every result is anchored to the domain list that was scanned
// (the line holding the domain) or to "domains.txt" for a single-domain run; the domain is in the message,
// logicalLocations and the fingerprint.

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

// fail/error -> error, warn -> warning, info -> note. pass is never reported. An info finding is only reported
// when it carries a remediation (an actionable note); purely informational record dumps stay out of code scanning.
export function sarifLevel(f) {
  if (f.status === 'fail' || f.status === 'error') return 'error';
  if (f.status === 'warn') return 'warning';
  if (f.status === 'info' && f.remediation) return 'note';
  return null;
}

const stripDot = (s) => String(s).replace(/[.\s]+$/, '');

// A relative, forward-slash path from the repository root, as GitHub requires. Absolute paths and "../" fall
// back to the file name so the uri stays stable regardless of where the CLI was started.
export function artifactUriFor(file) {
  if (!file || file === '-') return 'domains.txt';
  const posix = String(file).replace(/\\/g, '/');
  if (path.posix.isAbsolute(posix) || /^[A-Za-z]:\//.test(posix) || posix.split('/').includes('..')) {
    return path.posix.basename(posix);
  }
  return path.posix.normalize(posix).replace(/^\.\//, '');
}

// results: [{ domain, line, findings }]
export function toSarif(results, { artifactUri = 'domains.txt' } = {}) {
  const used = new Map(); // rule id -> rule object, in first-seen order
  const fingerprints = new Map();
  const sarifResults = [];

  for (const { domain, line = 1, findings } of results) {
    for (const f of findings) {
      const level = sarifLevel(f);
      if (!level) continue;
      const rule = ruleFor(f);
      if (!used.has(rule.id)) used.set(rule.id, rule);
      const base = createHash('sha256').update(`${rule.id}\n${domain}\n${f.key ?? ''}`).digest('hex').slice(0, 32);
      const n = (fingerprints.get(base) || 0) + 1;
      fingerprints.set(base, n);
      const text = [`${domain}: ${f.title}`, f.detail && stripDot(f.detail), f.remediation && `Remediation: ${stripDot(f.remediation)}`]
        .filter(Boolean).join('. ') + '.';
      sarifResults.push({
        ruleId: rule.id,
        level,
        message: { text },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: artifactUri },
            region: { startLine: line, startColumn: 1, endLine: line, endColumn: 1 },
          },
          logicalLocations: [{ name: domain, fullyQualifiedName: domain, kind: 'resource' }],
        }],
        partialFingerprints: { primaryLocationLineHash: `${base}:${n}` },
        properties: { domain, check: f.check, status: f.status },
      });
    }
  }

  const rules = [...used.values()].map((r) => ({
    id: r.id,
    shortDescription: { text: r.title },
    fullDescription: { text: `${r.title}. ${r.help}` },
    help: { text: r.help, markdown: r.help },
    helpUri: `${REPO_URL}/blob/main/docs/checks.md`,
    defaultConfiguration: { level: r.level },
    properties: { tags: ['external-posture', r.id.split('/')[0]], precision: 'high' },
  }));
  // ruleIndex points into driver.rules (same order as `used`).
  const index = new Map(rules.map((r, i) => [r.id, i]));
  for (const r of sarifResults) r.ruleIndex = index.get(r.ruleId);

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: NAME,
          version: VERSION,
          semanticVersion: VERSION,
          informationUri: REPO_URL,
          rules,
        },
      },
      invocations: [{ executionSuccessful: true }],
      results: sarifResults,
      properties: { domainsChecked: results.length },
    }],
  };
}

// Structural check of the properties GitHub code scanning requires (docs: "SARIF support for code scanning").
// Not a full JSON-Schema validation; returns a list of problems, empty when the shape is acceptable.
export function validateSarifShape(log) {
  const errors = [];
  const bad = (msg) => errors.push(msg);
  const str = (v) => typeof v === 'string' && v.length > 0;
  const posInt = (v) => Number.isInteger(v) && v >= 1;
  if (!str(log?.$schema)) bad('$schema missing');
  if (log?.version !== '2.1.0') bad('version must be "2.1.0"');
  if (!Array.isArray(log?.runs) || log.runs.length < 1 || log.runs.length > 20) { bad('runs must hold 1-20 runs'); return errors; }
  log.runs.forEach((run, ri) => {
    const at = `runs[${ri}]`;
    const driver = run?.tool?.driver;
    if (!str(driver?.name)) bad(`${at}.tool.driver.name missing`);
    if (!Array.isArray(driver?.rules)) bad(`${at}.tool.driver.rules must be an array`);
    const ids = new Set();
    (driver?.rules || []).forEach((r, i) => {
      if (!str(r.id)) bad(`${at}.rules[${i}].id missing`);
      else if (ids.has(r.id)) bad(`${at}.rules[${i}].id duplicated: ${r.id}`);
      else ids.add(r.id);
      for (const k of ['shortDescription', 'fullDescription', 'help']) {
        if (!str(r[k]?.text)) bad(`${at}.rules[${i}].${k}.text missing`);
      }
      if (r.defaultConfiguration && !['note', 'warning', 'error', 'none'].includes(r.defaultConfiguration.level)) {
        bad(`${at}.rules[${i}].defaultConfiguration.level invalid`);
      }
    });
    if (!Array.isArray(run?.results)) { bad(`${at}.results must be an array`); return; }
    if (run.results.length > 25_000) bad(`${at}.results exceeds GitHub's 25000 limit`);
    const hashes = new Set();
    run.results.forEach((res, i) => {
      const p = `${at}.results[${i}]`;
      if (!ids.has(res.ruleId)) bad(`${p}.ruleId "${res.ruleId}" is not in driver.rules`);
      if (res.ruleIndex !== undefined && driver.rules[res.ruleIndex]?.id !== res.ruleId) bad(`${p}.ruleIndex does not match ruleId`);
      if (!['note', 'warning', 'error'].includes(res.level)) bad(`${p}.level invalid`);
      if (!str(res.message?.text)) bad(`${p}.message.text missing`);
      if (!Array.isArray(res.locations) || res.locations.length < 1) bad(`${p}.locations missing`);
      (res.locations || []).forEach((loc, li) => {
        const pl = loc.physicalLocation;
        const uri = pl?.artifactLocation?.uri;
        if (!str(uri)) bad(`${p}.locations[${li}] artifactLocation.uri missing`);
        else if (/^[a-z][a-z0-9+.-]*:/i.test(uri) || uri.startsWith('/') || uri.includes('\\')) bad(`${p} uri must be a relative forward-slash path: ${uri}`);
        for (const k of ['startLine', 'startColumn', 'endLine', 'endColumn']) {
          if (!posInt(pl?.region?.[k])) bad(`${p}.locations[${li}].region.${k} must be a positive integer`);
        }
      });
      const h = res.partialFingerprints?.primaryLocationLineHash;
      if (!str(h)) bad(`${p}.partialFingerprints.primaryLocationLineHash missing`);
      else if (hashes.has(h)) bad(`${p} fingerprint not unique: ${h}`);
      else hashes.add(h);
    });
    (run.invocations || []).forEach((inv, i) => {
      if (typeof inv.executionSuccessful !== 'boolean') bad(`${at}.invocations[${i}].executionSuccessful must be boolean`);
    });
  });
  return errors;
}
