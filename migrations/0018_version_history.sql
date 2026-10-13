-- Several people working on one app. apps.last_version is the last version number handed out: a deploy takes the next
-- one in a single UPDATE before it writes any files, so two deploys at once never share a number (and so never write
-- into the same <app id>/<n>/ folder), and a deleted version's number is never used again.
-- versions.based_on is the version a deploy said its files started from ("base_version"), NULL when it did not say.
-- uploads.base_version remembers it for a deploy by upload address.
ALTER TABLE apps ADD COLUMN last_version INTEGER;
UPDATE apps SET last_version = (SELECT MAX(n) FROM versions WHERE versions.app_id = apps.id);
ALTER TABLE versions ADD COLUMN based_on INTEGER;
ALTER TABLE uploads ADD COLUMN base_version INTEGER;
