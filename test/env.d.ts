declare module 'cloudflare:test' {
  interface ProvidedEnv {
    DB: D1Database;
    TEST_MIGRATIONS: D1Migration[];
    SECRET_KEY: string;
    ADMIN_TOKEN: string;
    PLAYLIST_URL: string;
    EPG_URL: string;
    PUBLIC_PLAYLIST: string;
    TOKEN_BINDING: string;
    FALLBACK_M3U_URL: string;
  }
}
