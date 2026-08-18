/**
 * Empty live DASH manifest returned when an authenticated /mpd/ request
 * hits a dead upstream. Mirrors the HLS error manifest: no origin leak,
 * players keep polling (`type="dynamic"` + a short minimumUpdatePeriod)
 * instead of concluding the stream has ended.
 */

export function buildErrorMpd(reason?: string): string {
  const comment = `CHRTV: channel temporarily unavailable${reason ? ` (${reason})` : ''}`;
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" type="dynamic" minimumUpdatePeriod="PT4S" profiles="urn:mpeg:dash:profile:isoff-live:2011">`,
    `  <!-- ${comment} -->`,
    '  <Period id="0"/>',
    '</MPD>',
    '',
  ].join('\n');
}

export function errorMpdResponse(requestId: string, reason?: string): Response {
  return new Response(buildErrorMpd(reason), {
    status: 200,
    headers: {
      'Content-Type': 'application/dash+xml',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'X-Request-ID': requestId,
      'X-CHRTV-Fallback': '1',
    },
  });
}
