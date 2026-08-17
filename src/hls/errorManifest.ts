/**
 * CHRTV error/fallback HLS manifest.
 * Returned when an *authenticated* request hits a dead upstream.
 * It is a valid, empty, ENDED media playlist: players (VLC, TiviMate,
 * IPTV Smarters, OTT Navigator, Kodi) parse it cleanly, show "stream ended"
 * and stop — no HTML parse errors, no infinite retry loop.
 * Never leaks upstream URLs, headers or stack traces.
 */
export function buildErrorManifest(): string {
  return [
    '#EXTM3U',
    '#EXT-X-VERSION:3',
    '#EXT-X-TARGETDURATION:6',
    '#EXT-X-MEDIA-SEQUENCE:0',
    '#EXT-X-PLAYLIST-TYPE:VOD',
    '# CHRTV: channel temporarily unavailable',
    '#EXT-X-ENDLIST',
    '',
  ].join('\n');
}

export function errorManifestResponse(requestId: string): Response {
  return new Response(buildErrorManifest(), {
    status: 200,
    headers: {
      'Content-Type': 'application/vnd.apple.mpegurl',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
      'X-CHRTV-Fallback': '1',
    },
  });
}
