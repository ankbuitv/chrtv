import { sha256Hex } from '../utils/crypto';
import { isSafeUpstreamUrl } from '../utils/urlsafe';

export interface ParsedChannel {
  id: string;
  name: string;
  url: string;
  tvgId: string;
  tvgLogo: string;
  group: string;
  position: number;
}

export interface ParseResult {
  channels: ParsedChannel[];
  categories: string[];
  skipped: number;
}

const MAX_PLAYLIST_BYTES = 5 * 1024 * 1024;
const MAX_CHANNELS = 5000;
const ATTR_RE = /([a-zA-Z0-9-]+)="([^"]*)"/g;

export class PlaylistError extends Error {}

function parseAttrs(line: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const m of line.matchAll(ATTR_RE)) attrs[m[1]!.toLowerCase()] = m[2]!;
  return attrs;
}

/**
 * Parse + validate + normalize an M3U playlist.
 * - stable channel id = sha256(normalizedUrl|name|tvgId) prefix
 * - unsafe / non-http(s) URLs are skipped
 * - duplicates (same id) collapse to the first occurrence
 */
export async function parsePlaylist(text: string): Promise<ParseResult> {
  if (text.length > MAX_PLAYLIST_BYTES) throw new PlaylistError('playlist too large');
  const lines = text.replace(/\r/g, '').split('\n');
  const firstMeaningful = lines.find((l) => l.trim().length > 0)?.trim() ?? '';
  if (!firstMeaningful.startsWith('#EXTM3U')) throw new PlaylistError('missing #EXTM3U header');

  const channels: ParsedChannel[] = [];
  const seen = new Set<string>();
  const categories: string[] = [];
  const catSeen = new Set<string>();
  let skipped = 0;
  let pending: { name: string; attrs: Record<string, string> } | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith('#EXTINF')) {
      const comma = line.lastIndexOf(',');
      const name = (comma >= 0 ? line.slice(comma + 1) : '').trim();
      pending = { name, attrs: parseAttrs(line) };
      continue;
    }
    if (line.startsWith('#')) continue; // other directives (e.g. #EXTVLCOPT) are ignored
    if (!pending) continue; // URL without EXTINF
    const { name, attrs } = pending;
    pending = null;
    if (!name || !isSafeUpstreamUrl(line)) {
      skipped++;
      continue;
    }
    const url = line;
    const tvgId = attrs['tvg-id'] ?? '';
    const tvgLogo = attrs['tvg-logo'] ?? '';
    const group = (attrs['group-title'] ?? 'Uncategorized').trim() || 'Uncategorized';
    const id = (await sha256Hex(`${url}|${name}|${tvgId}`)).slice(0, 16);
    if (seen.has(id)) {
      skipped++;
      continue;
    }
    seen.add(id);
    if (!catSeen.has(group)) {
      catSeen.add(group);
      categories.push(group);
    }
    channels.push({ id, name, url, tvgId, tvgLogo, group, position: channels.length });
    if (channels.length > MAX_CHANNELS) throw new PlaylistError('too many channels');
  }

  if (channels.length === 0) throw new PlaylistError('no valid channels in playlist');
  return { channels, categories, skipped };
}
