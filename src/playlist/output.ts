import type { ChannelRow, Env } from '../types';
import { listActiveChannels } from '../db/channels';
import { createToken, TOKEN_STABILITY_WINDOW, tokenBindingSeed, type TokenBinding } from '../token';
import { getSetting } from '../db/settings';
import { parsePlayOpts, resolvedKind, tokenHintsFromPlayOpts } from './playOpts';
import { getViewerLease } from './viewLease';

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
  /** Tokenized CHRTV manifest URL (`/hls/{token}.m3u8` or `/mpd/{token}.mpd`). */
  url: string;
  /** Manifest kind the player should use. */
  kind: 'hls' | 'mpd';
  /** ClearKey kid/key when the source playlist declared one. */
  clearkey?: { kid: string; key: string };
}

export interface ChannelEntries {
  entries: ChannelEntry[];
  /** Tokenized EPG URL bound to the same identity. */
  epgUrl: string;
}

function mediaPath(origin: string, token: string, kind: 'hls' | 'mpd'): string {
  return kind === 'mpd' ? `${origin}/mpd/${token}.mpd` : `${origin}/hls/${token}.m3u8`;
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
  req?: Request,
): Promise<ChannelEntries> {
  const channels = await listActiveChannels(env.DB);
  const viewerLease = req ? await getViewerLease(req, env, binding) : undefined;
  const ttlSetting = Number(await getSetting(env.DB, 'playlist_token_ttl'));
  const ttl = Number.isFinite(ttlSetting) && ttlSetting > 60 ? ttlSetting : DEFAULT_PLAYLIST_TOKEN_TTL;
  const now = Math.floor(Date.now() / 1000);

  // Lease-pinned (or legacy quantized) issue time + deterministic IV:
  // refetching the playlist while playback is active yields the SAME channel
  // URLs. The binding is part of plaintext and the IV seed, and the rolling
  // lease changes every URL after the viewer has been idle.
  // Pin issue time to the viewer generation so a playlist remains byte-stable
  // across ordinary 10-minute token buckets for as long as playback is active.
  const iat = viewerLease?.issuedAt ?? Math.floor(now / TOKEN_STABILITY_WINDOW) * TOKEN_STABILITY_WINDOW;
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
    channels.map((ch) => {
      const hints = tokenHintsFromPlayOpts(ch.play_opts, ch.url);
      return createToken(
        env.SECRET_KEY,
        { u: ch.url, iat, exp, k: 'm', c: ch.id, ...binding, ...(viewerLease ? { l: viewerLease.id } : {}), ...hints },
        `ch|${iat}|${exp}|${ch.id}|${ch.url}|${bindingSeed}|${viewerLease?.id ?? ''}`,
      );
    }),
  );

  const entries: ChannelEntry[] = channels.map((ch: ChannelRow, i: number) => {
    const opts = parsePlayOpts(ch.play_opts);
    const kind = resolvedKind(opts, ch.url);
    const entry: ChannelEntry = {
      id: ch.id,
      name: ch.name,
      group: ch.category_name ?? 'Uncategorized',
      logo: ch.tvg_logo,
      tvgId: ch.tvg_id,
      url: mediaPath(origin, tokens[i]!, kind),
      kind,
    };
    if (opts.clearkey) entry.clearkey = opts.clearkey;
    return entry;
  });
  return { entries, epgUrl };
}

/**
 * Generate the user-facing M3U. Every channel entry points to a tokenized
 * /hls/ or /mpd/ URL, so raw upstream URLs never appear in the playlist.
 * DASH + ClearKey channels re-emit the Kodi license props (kid:key only —
 * never the upstream origin or stream_headers) so TiviMate/Kodi can decrypt.
 */
export async function buildPlaylist(
  env: Env,
  origin: string,
  binding: TokenBinding = {},
  absoluteExpiry?: number | null,
  req?: Request,
): Promise<string> {
  const { entries, epgUrl } = await buildChannelEntries(env, origin, binding, absoluteExpiry, req);
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
    if (ch.kind === 'mpd') {
      lines.push('#KODIPROP:inputstreamaddon=inputstream.adaptive');
      lines.push('#KODIPROP:inputstream.adaptive.manifest_type=mpd');
      if (ch.clearkey) {
        lines.push('#KODIPROP:inputstream.adaptive.license_type=clearkey');
        lines.push(`#KODIPROP:inputstream.adaptive.license_key=${ch.clearkey.kid}:${ch.clearkey.key}`);
      }
    }
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
