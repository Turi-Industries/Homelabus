-- A manual step attested before its app is installed: `pending_guides` needs the app's row,
-- which only an install writes, so a DNS record could be attested only after an --apply had
-- refused to start for want of it. Consumed by `add_guide`.
CREATE TABLE attested_ahead (
    app    TEXT NOT NULL,
    id     TEXT NOT NULL,
    forced INTEGER NOT NULL,
    PRIMARY KEY (app, id)
) STRICT;
