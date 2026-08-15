import type { ChannelRow, Env } from '../types';
import { listActiveChannels } from '../db/channels';
import { createToken, TOKEN_STABILITY_WINDOW } from '../token';
import { getSetting } from '../db/settings';

const DEFAULT_PLAYLIST_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days

function escapeAttr(v: string): string {
  return v.replace(/"/g, "'");
}

function escapeName(v: string): string {
  return v.replace(/[\r\n]/g, ' ').trim();
}

/**
 * Generate the user-facing M3U. Every channel entry points to
 * {origin}/hls/{token}.m3u8 — an encrypted channel-level token that embeds the
 * upstream URL + channel id. Upstream URLs never appear in the output.
 */
export async function buildPlaylist(env: Env, origin: string): Promise<string> {
  const channels = await listActiveChannels(env.DB);
  const ttlSetting = Number(await getSetting(env.DB, 'playlist_token_ttl'));
  const ttl = Number.isFinite(ttlSetting) && ttlSetting > 60 ? ttlSetting : DEFAULT_PLAYLIST_TOKEN_TTL;
  const now = Math.floor(Date.now() / 1000);

  const epgUrl = `${origin}/xmltv.php`;
  const lines: string[] = [`#EXTM3U url-tvg="${epgUrl}" x-tvg-url="${epgUrl}"`];

  // Quantized issue time + deterministic IV: refetching the playlist yields the
  // SAME channel URLs, so players keep their channel mapping/EPG bindings and
  // do not restart every stream after each playlist refresh.
  const iat = Math.floor(now / TOKEN_STABILITY_WINDOW) * TOKEN_STABILITY_WINDOW;
  const tokens = await Promise.all(
    channels.map((ch) =>
      createToken(env.SECRET_KEY, { u: ch.url, iat, exp: iat + ttl, k: 'm', c: ch.id }, `ch|${iat}|${ch.id}|${ch.url}`),
    ),
  );

  channels.forEach((ch: ChannelRow, i: number) => {
    const attrs = [
      `tvg-id="${escapeAttr(ch.tvg_id)}"`,
      `tvg-name="${escapeAttr(ch.name)}"`,
      ch.tvg_logo ? `tvg-logo="${escapeAttr(ch.tvg_logo)}"` : '',
      `group-title="${escapeAttr(ch.category_name ?? 'Uncategorized')}"`,
    ]
      .filter(Boolean)
      .join(' ');
    lines.push(`#EXTINF:-1 ${attrs},${escapeName(ch.name)}`);
    lines.push(`${origin}/hls/${tokens[i]}.m3u8`);
  });

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
