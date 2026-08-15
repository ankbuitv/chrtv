import { applyD1Migrations, env } from 'cloudflare:test';

// Apply migrations to the test D1 database before any test runs.
await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);
