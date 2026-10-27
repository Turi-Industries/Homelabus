-- One address, one owner. `user_mailboxes` is keyed by (user, local): two accounts
-- could both claim `contact@`, and each would then be offered the other's mail as
-- its own — its aliases, its default address pushed to PocketID.
--
-- A trigger rather than a UNIQUE index: an installation that already holds such a
-- pair would fail this migration, and the upgrade with it. What exists is left for a
-- person to sort out; nothing new may join it.
CREATE TRIGGER user_mailboxes_one_owner
BEFORE INSERT ON user_mailboxes
WHEN EXISTS (
    SELECT 1 FROM user_mailboxes
    WHERE local = NEW.local AND domain = NEW.domain AND user <> NEW.user
)
BEGIN
    SELECT RAISE(ABORT, 'this address is another account''s mailbox');
END;
