import type { ChannelRow, Env } from '../types';
import { listActiveChannels } from '../db/channels';
import { createToken, TOKEN_STABILITY_WINDOW, tokenBindingSeed, type TokenBinding } from '../token';
import { getSetting } from '../db/settings';

const DEFAULT_PLAYLIST_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days

function escapeAttr(v: string): string {
  return v.replace(/"/g, "'");
}

function escapeName(v: string): string {
  return v.replace(/[\r\n]/g, ' ').trim();
}

export interface ChannelEntry {
  id: string;
  name: string;
  group: string;
  logo: string;
  tvgId: string;
  /** Tokenized CHRTV manifest URL ({origin}/hls/{token}.m3u8). */
  url: string;
}

export interface ChannelEntries {
  entries: ChannelEntry[];
  /** Tokenized EPG URL bound to the same identity. */
  epgUrl: string;
}

/**
 * Mint tokenized channel entries (+ EPG URL) for one identity. Shared by the
 * classic M3U renderer (buildPlaylist) and the /xem web player JSON API, so
 * both surfaces hand out byte-identical, stable tokens for the same client.
 * Raw upstream URLs never appear in the output.
 */
export async function buildChannelEntries(
  env: Env,
  origin: string,
  binding: TokenBinding = {},
  absoluteExpiry?: number | null,
): Promise<ChannelEntries> {
  const channels = await listActiveChannels(env.DB);
  const ttlSetting = Number(await getSetting(env.DB, 'playlist_token_ttl'));
  const ttl = Number.isFinite(ttlSetting) && ttlSetting > 60 ? ttlSetting : DEFAULT_PLAYLIST_TOKEN_TTL;
  const now = Math.floor(Date.now() / 1000);

  // Quantized issue time + deterministic IV: refetching the playlist yields the
  // SAME channel URLs for the same client identity, so players keep their
  // channel mapping/EPG bindings. The binding is part of both plaintext and IV
  // seed, making tokens different across IP/MAC/user/access-key identities.
  const iat = Math.floor(now / TOKEN_STABILITY_WINDOW) * TOKEN_STABILITY_WINDOW;
  const bindingSeed = tokenBindingSeed(binding);
  const configuredExp = iat + ttl;
  // Authenticated playlist capabilities must never outlive their account/key.
  const exp =
    absoluteExpiry !== null && absoluteExpiry !== undefined && Number.isFinite(absoluteExpiry) && absoluteExpiry > 0
      ? Math.min(configuredExp, Math.floor(absoluteExpiry))
      : configuredExp;
  // EPG is access-controlled by the same encrypted identity token as media.
  // The sentinel URL is never fetched; it keeps the shared token schema strict
  // without exposing EPG_URL or allowing an ordinary media token on /epg/.
  const epgToken = await createToken(
    env.SECRET_KEY,
    { u: 'https://epg-token.chrtv.invalid/xmltv.xml', iat, exp, k: 'e', ...binding },
    `e|${iat}|${exp}|${bindingSeed}`,
  );
  const epgUrl = `${origin}/epg/${epgToken}.xml`;

  const tokens = await Promise.all(
    channels.map((ch) =>
      createToken(
        env.SECRET_KEY,
        { u: ch.url, iat, exp, k: 'm', c: ch.id, ...binding },
        `ch|${iat}|${exp}|${ch.id}|${ch.url}|${bindingSeed}`,
      ),
    ),
  );

  const entries: ChannelEntry[] = channels.map((ch: ChannelRow, i: number) => ({
    id: ch.id,
    name: ch.name,
    group: ch.category_name ?? 'Uncategorized',
    logo: ch.tvg_logo,
    tvgId: ch.tvg_id,
    url: `${origin}/hls/${tokens[i]}.m3u8`,
  }));
  return { entries, epgUrl };
}

/**
 * Generate the user-facing M3U. Every channel entry points to
 * {origin}/hls/{token}.m3u8, so raw upstream URLs never appear in the playlist.
 * A channel on a port the Worker cannot fetch remains opaque but fails closed
 * to a proxyable fallback/error manifest; CHRTV never redirects to its origin.
 */
export async function buildPlaylist(
  env: Env,
  origin: string,
  binding: TokenBinding = {},
  absoluteExpiry?: number | null,
): Promise<string> {
  const { entries, epgUrl } = await buildChannelEntries(env, origin, binding, absoluteExpiry);
  const lines: string[] = [`#EXTM3U url-tvg="${epgUrl}" x-tvg-url="${epgUrl}"`];

  for (const ch of entries) {
    const attrs = [
      `tvg-id="${escapeAttr(ch.tvgId)}"`,
      `tvg-name="${escapeAttr(ch.name)}"`,
      ch.logo ? `tvg-logo="${escapeAttr(ch.logo)}"` : '',
      `group-title="${escapeAttr(ch.group)}"`,
    ]
      .filter(Boolean)
      .join(' ');
    lines.push(`#EXTINF:-1 ${attrs},${escapeName(ch.name)}`);
    lines.push(ch.url);
  }

  return lines.join('\n') + '\n';
}

export function playlistResponse(body: string, requestId: string, isHead: boolean): Response {
  return new Response(isHead ? null : body, {
    status: 200,
    headers: {
      'Content-Type': 'application/x-mpegurl; charset=utf-8',
      'Content-Disposition': 'inline; filename="tv.m3u"',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
    },
  });
}
