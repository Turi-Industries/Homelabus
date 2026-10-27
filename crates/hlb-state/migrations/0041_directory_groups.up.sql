-- The groups Homelabus has written into an app's organisation, one per role. The
-- import route never removes or empties a group it is not sent: one whose role is gone
-- is sent once more, with no member, and only then forgotten here.
CREATE TABLE directory_groups (
    app         TEXT NOT NULL,
    external_id TEXT NOT NULL,
    PRIMARY KEY (app, external_id)
) STRICT;
