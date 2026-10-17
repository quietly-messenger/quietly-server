-- Delivery timing jitter (TASK-001 B, §15 delivery_jitter_ms). A message
-- becomes fetchable and notifiable only at not_before >= server_ts. Existing
-- rows are backfilled to server_ts so they remain immediately deliverable.
ALTER TABLE messages ADD COLUMN not_before TIMESTAMPTZ;
UPDATE messages SET not_before = server_ts;
ALTER TABLE messages ALTER COLUMN not_before SET NOT NULL;
