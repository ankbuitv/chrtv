import type { ChannelRow } from '../types';

const CHANNEL_COLUMNS =
  'c.id, c.xtream_id, c.name, c.url, c.tvg_id, c.tvg_logo, c.category_id, c.position, c.active, c.play_opts, cat.name AS category_name';

export async function listActiveChannels(db: D1Database): Promise<ChannelRow[]> {
  const { results } = await db
    .prepare(
      `SELECT ${CHANNEL_COLUMNS} FROM channels c LEFT JOIN categories cat ON cat.id = c.category_id
       WHERE c.active = 1 ORDER BY c.position ASC`,
    )
    .all<ChannelRow>();
  return results;
}

export async function getChannelByXtreamId(db: D1Database, xtreamId: number): Promise<ChannelRow | null> {
  return db
    .prepare(
      `SELECT ${CHANNEL_COLUMNS} FROM channels c LEFT JOIN categories cat ON cat.id = c.category_id
       WHERE c.xtream_id = ? AND c.active = 1`,
    )
    .bind(xtreamId)
    .first<ChannelRow>();
}

export async function listCategories(db: D1Database): Promise<Array<{ id: number; name: string; position: number }>> {
  const { results } = await db
    .prepare('SELECT id, name, position FROM categories ORDER BY position ASC')
    .all<{ id: number; name: string; position: number }>();
  return results;
}
