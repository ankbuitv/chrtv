-- Per-channel playback hints parsed from #EXTVLCOPT / #KODIPROP
-- (manifest kind, Referer/UA, extra headers, ClearKey). Empty string = none.
ALTER TABLE channels ADD COLUMN play_opts TEXT NOT NULL DEFAULT '';
