/**
 * CHRTV error/fallback HLS manifest.
 * Returned when an *authenticated* request hits a dead upstream.
 *
 * It is a valid, EMPTY, still-LIVE media playlist — deliberately WITHOUT
 * `#EXT-X-ENDLIST`. The old fallback ended with ENDLIST, which players
 * (VLC especially, but also TiviMate/IPTV Smarters/OTT Navigator/Kodi)
 * interpret as "this channel is OVER": the stream stops dead and the user
 * has to re-open the channel manually every single time the upstream had a
 * one-second hiccup. A live playlist with no segments means "nothing to play
 * right this moment": players keep polling the manifest, so the channel
 * RECOVERS BY ITSELF as soon as the upstream comes back. No HTML parse
 * errors, no infinite retry loop, no dead channels after a blip.
 *
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
    '#EXT-X-TARGETDURATION:4',
    '#EXT-X-MEDIA-SEQUENCE:0',
    `# CHRTV: channel temporarily unavailable, player keeps retrying${reason ? ` (${reason})` : ''}`,
    // No #EXT-X-ENDLIST on purpose: this is a live placeholder, not a dead VOD.
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
