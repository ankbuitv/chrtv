/**
 * CHRTV error/fallback HLS manifest.
 * Returned when an *authenticated* request hits a dead upstream.
 * It is a valid, empty, ENDED media playlist: players (VLC, TiviMate,
 * IPTV Smarters, OTT Navigator, Kodi) parse it cleanly, show "stream ended"
 * and stop — no HTML parse errors, no infinite retry loop.
 * Never leaks upstream URLs, headers or stack traces.
 *
 * `reason` is an optional internal error code (e.g. UNSUPPORTED_PORT,
 * UPSTREAM_4XX, INVALID_HLS) appended to the comment so operators can tell
 * from a player's log why a channel failed. Only stable error codes are ever
 * embedded — never URLs, hostnames or secrets.
 */
export function buildErrorManifest(reason?: string): string {
  return [
    '#EXTM3U',
    '#EXT-X-VERSION:3',
    '#EXT-X-TARGETDURATION:6',
    '#EXT-X-MEDIA-SEQUENCE:0',
    '#EXT-X-PLAYLIST-TYPE:VOD',
    `# CHRTV: channel temporarily unavailable${reason ? ` (${reason})` : ''}`,
    '#EXT-X-ENDLIST',
    '',
  ].join('\n');
}

export function errorManifestResponse(requestId: string, reason?: string): Response {
  return new Response(buildErrorManifest(reason), {
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
