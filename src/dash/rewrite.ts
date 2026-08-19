import { type TokenBinding } from '../token';
import { mintProxyUrl, MintError, type MintOptions } from '../proxy/mint';
import { resolveUri } from '../hls/rewrite';

/**
 * DASH (MPD) rewriter.
 *
 * HLS lists every segment URL; DASH often uses SegmentTemplate so the player
 * builds URLs itself (`seg_$Number$.m4s`). We cannot pre-tokenize every
 * possible segment, so:
 *  - every <BaseURL> becomes an absolute `/dseg/{token}/` prefix whose token
 *    encodes the upstream directory;
 *  - relative media/initialization templates stay relative and resolve against
 *    that prefix on the player side;
 *  - absolute media/initialization/sourceURL values are rewritten to /seg/
 *    (concrete file) or /dseg/ (template / directory).
 *
 * Fail closed: an URL we cannot safely proxy rejects the whole MPD rather
 * than leaking the origin.
 */

const MAX_MPD_BYTES = 2 * 1024 * 1024;

const URL_ATTRS = new Set(['media', 'initialization', 'sourceurl', 'bitstreamswitching', 'index', 'href']);

export class DashError extends Error {}

export function looksLikeMpd(text: string): boolean {
  const head = text.trimStart().slice(0, 4096);
  if (!head.startsWith('<') && !head.startsWith('<?')) return false;
  return /<MPD[\s>/]/i.test(head);
}

export interface DashRewriteOptions {
  secret: string;
  baseUrl: string;
  publicOrigin: string;
  binding?: TokenBinding;
  channelId?: string;
  leaseId?: string;
  absoluteExpiry?: number;
  now?: number;
  rf?: string;
  ua?: string;
  xh?: string;
}

function mintOpts(opts: DashRewriteOptions): MintOptions {
  return {
    secret: opts.secret,
    publicOrigin: opts.publicOrigin,
    binding: opts.binding,
    ...(opts.channelId ? { channelId: opts.channelId } : {}),
    ...(opts.leaseId ? { leaseId: opts.leaseId } : {}),
    ...(opts.absoluteExpiry !== undefined ? { absoluteExpiry: opts.absoluteExpiry } : {}),
    ...(opts.now !== undefined ? { now: opts.now } : {}),
    ...(opts.rf ? { rf: opts.rf } : {}),
    ...(opts.ua ? { ua: opts.ua } : {}),
    ...(opts.xh ? { xh: opts.xh } : {}),
  };
}

async function mint(opts: DashRewriteOptions, upstream: string, kind: 's' | 'b'): Promise<string> {
  try {
    return await mintProxyUrl(mintOpts(opts), upstream, kind);
  } catch (err) {
    throw new DashError(err instanceof MintError ? err.message : 'token mint failed');
  }
}

function hasTemplateVars(value: string): boolean {
  return /\$[A-Za-z][A-Za-z0-9_]*(?:%[^$]+)?\$/.test(value);
}

/** Directory of an MPD URL, preserving a query token (`?token=` / `?sign=`). */
export function mpdDirectory(baseUrl: string): string {
  const u = new URL(baseUrl);
  u.hash = '';
  if (!u.pathname.endsWith('/')) {
    const slash = u.pathname.lastIndexOf('/');
    u.pathname = slash >= 0 ? u.pathname.slice(0, slash + 1) : '/';
  }
  return u.toString();
}

/**
 * Join a DASH path suffix onto a tokenized base. Rejects anything that would
 * escape the base directory or switch origin (path traversal, absolute URLs).
 */
export function joinDashPath(base: string, suffix: string): string | null {
  if (!suffix || suffix.length > 2048) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(suffix);
  } catch {
    return null;
  }
  if (decoded.includes('\\') || decoded.includes('\0')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(decoded) || decoded.startsWith('//') || decoded.startsWith('/')) return null;
  if (decoded.split(/[/?#]/)[0]?.split('/').some((p) => p === '..')) return null;
  // Also reject `foo/../bar` anywhere in the path.
  const pathOnly = decoded.split(/[?#]/, 1)[0] ?? '';
  if (pathOnly.split('/').some((p) => p === '..')) return null;

  try {
    const baseUrl = new URL(base);
    const baseHref = baseUrl.pathname.endsWith('/') ? baseUrl.href : `${baseUrl.origin}${baseUrl.pathname.replace(/\/[^/]*$/, '/')}${baseUrl.search}${baseUrl.hash}`;
    const joined = new URL(decoded, baseHref);
    if (joined.origin !== baseUrl.origin) return null;
    const baseDir = baseUrl.pathname.endsWith('/') ? baseUrl.pathname : baseUrl.pathname.replace(/\/[^/]*$/, '/');
    if (!joined.pathname.startsWith(baseDir)) return null;
    if (baseUrl.search && !joined.search) joined.search = baseUrl.search;
    return joined.toString();
  } catch {
    return null;
  }
}

function isAbsoluteUrl(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith('//');
}

async function rewriteUrlValue(value: string, opts: DashRewriteOptions, asDirectory: boolean): Promise<string> {
  const trimmed = value.trim();
  if (!trimmed || /^(data:|urn:|cid:)/i.test(trimmed)) return value;

  const abs = resolveUri(trimmed, opts.baseUrl);
  if (!abs) throw new DashError('invalid mpd url');

  if (asDirectory || hasTemplateVars(trimmed) || trimmed.endsWith('/')) {
    // Encode the directory prefix; leave the template/filename as a suffix
    // so dash.js can still expand $Number$ / $Time$ itself.
    const dir = trimmed.endsWith('/') || asDirectory ? (abs.endsWith('/') ? abs : abs.replace(/\/?$/, '/')) : mpdDirectory(abs);
    const prefix = await mint(opts, dir.endsWith('/') ? dir : `${dir}${dir.includes('?') ? '' : '/'}`, 'b');
    if (asDirectory || trimmed.endsWith('/')) return prefix;
    const name = (abs.split('?')[0] ?? abs).split('/').pop() ?? '';
    // Preserve the original template string (with $Number$) rather than the
    // resolved filename, which may have lost the `$` placeholders if they
    // were percent-encoded in the URL constructor.
    const originalName = trimmed.split('/').pop() ?? name;
    return `${prefix}${originalName}`;
  }
  return mint(opts, abs, 's');
}

async function rewriteAttributes(xml: string, opts: DashRewriteOptions): Promise<string> {
  const re = /(\s)([A-Za-z_:][A-Za-z0-9:._-]*)(\s*=\s*)("([^"]*)"|'([^']*)')/g;
  const matches = [...xml.matchAll(re)];
  if (matches.length === 0) return xml;
  let out = '';
  let last = 0;
  for (const m of matches) {
    const idx = m.index ?? 0;
    out += xml.slice(last, idx);
    const name = m[2] ?? '';
    const quote = (m[4] ?? '').startsWith("'") ? "'" : '"';
    const value = m[5] ?? m[6] ?? '';
    if (URL_ATTRS.has(name.toLowerCase()) && value && isAbsoluteUrl(value)) {
      const rewritten = await rewriteUrlValue(value, opts, false);
      out += `${m[1]}${name}${m[3]}${quote}${rewritten}${quote}`;
    } else {
      out += m[0];
    }
    last = idx + m[0].length;
  }
  out += xml.slice(last);
  return out;
}

async function rewriteBaseUrls(xml: string, opts: DashRewriteOptions): Promise<string> {
  const re = /<BaseURL(\s[^>]*)?>([\s\S]*?)<\/BaseURL>/gi;
  const matches = [...xml.matchAll(re)];
  if (matches.length === 0) return xml;
  let out = '';
  let last = 0;
  for (const m of matches) {
    const idx = m.index ?? 0;
    out += xml.slice(last, idx);
    const attrs = m[1] ?? '';
    const rewritten = await rewriteUrlValue((m[2] ?? '').trim() || './', opts, true);
    out += `<BaseURL${attrs}>${rewritten}</BaseURL>`;
    last = idx + m[0].length;
  }
  out += xml.slice(last);
  return out;
}

async function rewriteLocations(xml: string, opts: DashRewriteOptions): Promise<string> {
  const re = /<Location(\s[^>]*)?>([\s\S]*?)<\/Location>/gi;
  const matches = [...xml.matchAll(re)];
  if (matches.length === 0) return xml;
  let out = '';
  let last = 0;
  for (const m of matches) {
    const idx = m.index ?? 0;
    out += xml.slice(last, idx);
    const attrs = m[1] ?? '';
    const value = (m[2] ?? '').trim();
    if (!value) {
      out += m[0];
    } else {
      const rewritten = await rewriteUrlValue(value, opts, false);
      out += `<Location${attrs}>${rewritten}</Location>`;
    }
    last = idx + m[0].length;
  }
  out += xml.slice(last);
  return out;
}

export async function rewriteMpd(text: string, opts: DashRewriteOptions): Promise<string> {
  if (text.length > MAX_MPD_BYTES) throw new DashError('manifest too large');
  if (!looksLikeMpd(text)) throw new DashError('not a DASH manifest');

  let xml = text;
  xml = await rewriteBaseUrls(xml, opts);
  xml = await rewriteLocations(xml, opts);
  xml = await rewriteAttributes(xml, opts);

  // No <BaseURL> at all → the implicit base is the MPD's own directory.
  // Inject one so relative SegmentTemplate paths go through /dseg/.
  if (!/<BaseURL[\s>]/i.test(xml)) {
    const prefix = await mint(opts, mpdDirectory(opts.baseUrl), 'b');
    xml = xml.replace(/<MPD(\s[^>]*)?>/i, (open) => `${open}\n  <BaseURL>${prefix}</BaseURL>`);
  }
  return xml;
}
