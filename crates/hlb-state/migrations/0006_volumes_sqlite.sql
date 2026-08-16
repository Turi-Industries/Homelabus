-- Le manifest déclarait `storage[].sqlite: true` depuis le début, et rien ne le
-- mémorisait : les bases SQLite étaient donc sauvegardées À CHAUD, ce que le §3.4
-- interdit explicitement. Un fichier SQLite copié pendant une écriture donne une
-- base restaurée corrompue, sans que rien ne le signale à la sauvegarde.
ALTER TABLE app_volumes ADD COLUMN sqlite INTEGER NOT NULL DEFAULT 0;
