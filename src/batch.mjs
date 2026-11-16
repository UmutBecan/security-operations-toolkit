import { normalizeDomain } from './domain.mjs';

export const MAX_FILE_BYTES = 1024 * 1024;
export const DEFAULT_CONCURRENCY = 4;
export const MAX_CONCURRENCY = 16;

// One domain per line. "#" starts a comment (full line or trailing), blank lines are ignored, a UTF-8 BOM is
// dropped, every remaining entry is validated with the same validator as a single-domain run, duplicates
// (after normalisation) keep their first line. Returns { entries: [{ domain, line }], invalid, duplicates }.
export function parseDomainList(text) {
  const entries = [];
  const invalid = [];
  const seen = new Set();
  let duplicates = 0;
  const lines = String(text).replace(/^﻿/, '').split(/\r?\n/);
  lines.forEach((raw, i) => {
    const input = raw.replace(/#.*$/, '').trim();
    if (!input) return;
    try {
      const domain = normalizeDomain(input);
      if (seen.has(domain)) duplicates += 1;
      else {
        seen.add(domain);
        entries.push({ domain, line: i + 1 });
      }
    } catch (e) {
      invalid.push({ line: i + 1, input, message: e.message });
    }
  });
  return { entries, invalid, duplicates };
}

// Runs fn over items with at most `limit` in flight; results keep input order.
export async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next;
      next += 1;
      results[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
}
