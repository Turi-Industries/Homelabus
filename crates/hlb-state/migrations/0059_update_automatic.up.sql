-- How far an update goes with nobody there, as the owner set it over the manifest's: one row
-- for the house (app ''), one per app that differs. An app's row wins over the house's.
CREATE TABLE update_automatic (
    app TEXT PRIMARY KEY,
    automatic TEXT NOT NULL CHECK (automatic IN ('none', 'patch', 'minor'))
);
