-- Where a restore held a service's volume. Scaled to 0 an NFS app has no task, and no pin says
-- where it ran: a restore stopped halfway could not be tried again. NULL: held by a copy, or
-- before this column.
ALTER TABLE service_holds ADD COLUMN node TEXT;
