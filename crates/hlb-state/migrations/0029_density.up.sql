-- How tightly a person's lists are set: `comfortable` or `compact`. NULL = comfortable.
ALTER TABLE user_prefs ADD COLUMN density TEXT;
