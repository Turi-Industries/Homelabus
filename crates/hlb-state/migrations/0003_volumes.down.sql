-- L'inventaire des volumes, pas les volumes eux-mêmes : les données Docker
-- survivent. En revanche, la sauvegarde ne saura plus QUOI sauvegarder tant que
-- les apps ne sont pas réinstallées.
DROP TABLE IF EXISTS app_volumes;
