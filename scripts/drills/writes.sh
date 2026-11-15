#!/bin/sh
#
# The moving-house drill's witnesses, run ON a lab machine (copied there by
# scripts/drills/available.sh): one write a second into each store the site carries,
# each holding the house's clock, so what reached the site says how much was lost.
#
#   writes.sh start    at home: the table, the row and the file; then a write a second
#   writes.sh stop     at home: the writer stopped
#   writes.sh newest   either side: "<database> <sqlite> <files>", the newest of each
#   writes.sh drop     at home, once the return is done: nothing of them left
#
# Written beside the apps, not through them: the WAL, Litestream and the volume pusher
# carry any write. Stopped before the return: written into PocketID's SQLite while the
# return replaces it, it would damage what came home.

set -eu

pg() {
    id=$(docker ps -qf label=com.docker.swarm.service.name=postgres-vital | head -n 1)
    # The app's role: a table the role cannot read fails the return's dump of its database.
    docker exec -i "$id" psql -U postgres -d vaultwarden -qAtX -c "SET ROLE vaultwarden" -c "$1"
}
# Neither machine has the sqlite3 CLI; both have Python.
sqlite() {
    python3 - "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect("/var/lib/docker/volumes/pocket-id-data/_data/pocket-id.db", timeout=10)
rows = c.execute(sys.argv[1]).fetchall()
c.commit()
print(rows[0][0] if rows else "")
PY
}
file=/var/lib/docker/volumes/vaultwarden-data/_data/hlb-witness
pidfile=/root/hlb-witness.pid

case "${1:-}" in
start)
    pg 'CREATE TABLE IF NOT EXISTS hlb_witness (at bigint)'
    sqlite 'CREATE TABLE IF NOT EXISTS hlb_witness (at INTEGER)' >/dev/null
    # Its own session: the SSH that started it ends at once.
    setsid "$0" loop </dev/null >/dev/null 2>&1 &
    echo $! >"$pidfile"
    ;;
loop)
    while :; do
        t=$(date +%s)
        pg "INSERT INTO hlb_witness VALUES ($t)" || true
        sqlite "INSERT INTO hlb_witness VALUES ($t)" >/dev/null || true
        echo "$t" >"$file.tmp" && mv -f "$file.tmp" "$file"
        sleep 1
    done
    ;;
stop)
    [ ! -f "$pidfile" ] || kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
    ;;
newest)
    echo "$(pg 'SELECT coalesce(max(at), 0) FROM hlb_witness' | tail -n 1)" \
        "$(sqlite 'SELECT coalesce(max(at), 0) FROM hlb_witness')" \
        "$(cat "$file" 2>/dev/null || echo 0)"
    ;;
drop)
    pg 'DROP TABLE IF EXISTS hlb_witness'
    sqlite 'DROP TABLE IF EXISTS hlb_witness' >/dev/null
    rm -f "$file"
    ;;
*)
    sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
