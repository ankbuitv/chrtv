import type { Env } from '../types';
import { getClientIp } from '../token';

export type AuthEventType = 'login' | 'playlist' | 'xtream' | 'access_key';
export type AuthEventOutcome = 'success' | 'failure' | 'blocked' | 'limit';

export interface AuthEvent {
  userId?: number | null;
  sessionId?: number | null;
  username?: string;
  eventType: AuthEventType;
  route: string;
  outcome: AuthEventOutcome;
}

/**
 * Persist a credential/playlist audit event without ever recording the request
 * URL, query string, password, access key, or session bearer token.
 *
 * The operator explicitly requested readable login addresses, so auth_events
 * stores the Cloudflare-observed IP verbatim. Security-ban tables remain HMAC
 * only. Event rows are removed after 30 days by scheduled cleanup.
 */
export async function recordAuthEvent(req: Request, env: Env, event: AuthEvent): Promise<void> {
  try {
    const ts = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO auth_events
         (user_id, session_id, username, event_type, route, outcome, ip_address, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        event.userId ?? null,
        event.sessionId ?? null,
        (event.username ?? '').slice(0, 128),
        event.eventType,
        event.route.slice(0, 64),
        event.outcome,
        getClientIp(req) ?? '',
        (req.headers.get('user-agent') ?? '').slice(0, 256),
        ts,
      )
      .run();
  } catch {
    // Audit failure must not turn valid credentials into an outage. Admin
    // status/log visibility will reveal a broken or unapplied migration.
  }
}
