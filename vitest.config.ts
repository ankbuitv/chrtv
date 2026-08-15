import { defineWorkersConfig, readD1Migrations } from '@cloudflare/vitest-pool-workers/config';
import path from 'node:path';

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, 'migrations'));
  return {
    test: {
      setupFiles: ['./test/setup.ts'],
      poolOptions: {
        workers: {
          singleWorker: true,
          wrangler: { configPath: './wrangler.toml' },
          miniflare: {
            bindings: {
              TEST_MIGRATIONS: migrations,
              SECRET_KEY: 'test-secret-key-0123456789abcdef',
              ADMIN_TOKEN: 'test-admin-token-0123456789',
              PLAYLIST_URL: 'https://raw.example.com/playlists/tv.m3u',
              EPG_URL: '',
              PUBLIC_PLAYLIST: 'true',
            },
          },
        },
      },
    },
  };
});
