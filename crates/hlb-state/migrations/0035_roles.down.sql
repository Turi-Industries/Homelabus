-- Back to a level per person and a profile per account. A role's mail limits that
-- match no profile come back as `standard`; per-app quotas and allowances are lost.
CREATE TABLE user_roles (
    user       TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    granted_by TEXT,
    granted_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
INSERT INTO user_roles (user, role, granted_by, granted_at)
SELECT u.name, r.level, u.role_granted_by, coalesce(u.role_granted_at, datetime('now'))
FROM users u JOIN roles r ON r.id = u.role;

ALTER TABLE users ADD COLUMN profile TEXT NOT NULL DEFAULT 'standard';
UPDATE users SET profile = coalesce((
    SELECT CASE WHEN r.max_mailboxes = 1 AND r.max_permanent_aliases = 0 THEN 'guest'
                WHEN r.max_mailboxes = 4294967295 THEN 'unlimited'
                ELSE 'standard' END
    FROM roles r WHERE r.id = users.role), 'standard');

ALTER TABLE invitations ADD COLUMN profile TEXT NOT NULL DEFAULT 'standard';
UPDATE invitations SET
    profile = coalesce((
        SELECT CASE WHEN r.max_mailboxes = 1 AND r.max_permanent_aliases = 0 THEN 'guest'
                    WHEN r.max_mailboxes = 4294967295 THEN 'unlimited'
                    ELSE 'standard' END
        FROM roles r WHERE r.id = invitations.role), 'standard'),
    role = coalesce((SELECT r.level FROM roles r WHERE r.id = invitations.role), 'user');

ALTER TABLE users DROP COLUMN role;
ALTER TABLE users DROP COLUMN role_granted_by;
ALTER TABLE users DROP COLUMN role_granted_at;
DROP TABLE app_roles;
DROP TABLE quota_applied;
DROP TABLE person_quotas;
DROP TABLE role_quotas;
DROP TABLE roles;
