-- 🔴 Destroys every access token. After a rollback the API accepts nobody
-- until new tokens are created — which is the right way to fail: closed beats wide
-- open.
DROP TABLE IF EXISTS api_tokens;
