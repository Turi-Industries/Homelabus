#!/usr/bin/env bash
#
# What a machine holds, one line each: "table <engine>/<database>/<table> <rows>" for every
# application table of the servers running here, "volume <name> <files>" for each volume named
# on the command line. Read through a pipe, on the house and on what replaces it, by
# `recovery.sh`: an assertion reads an app's settings, and a server restored empty passes it.
#
# Usage: witness.sh [volume ...]

set -uo pipefail

pg=$(docker ps -qf 'name=^postgres\.1\.')
if [[ -n $pg ]]; then
    for db in $(docker exec "$pg" psql -U postgres -Atc \
        "select datname from pg_database where not datistemplate and datname <> 'postgres'"); do
        docker exec "$pg" psql -U postgres -d "$db" -AtF' ' -c "
            select 'table postgres/$db/' || schemaname || '.' || tablename,
                   (xpath('/row/c/text()', query_to_xml(
                       format('select count(*) c from %I.%I', schemaname, tablename),
                       false, true, '')))[1]::text
            from pg_tables where schemaname not in ('pg_catalog', 'information_schema')"
    done
fi

maria=$(docker ps -qf 'name=^mariadb\.1\.')
if [[ -n $maria ]]; then
    # The password stays in the container: read there, from its own secret.
    docker exec -i "$maria" sh -c 'export MYSQL_PWD=$(cat /run/secrets/root-password)
        q=$(mariadb -uroot -N -e "
            select group_concat(concat(
                \"select \", char(39), \"table mariadb/\", table_schema, \"/\", table_name, char(39),
                \", count(*) from \`\", table_schema, \"\`.\`\", table_name, \"\`\") separator \" union all \")
            from information_schema.tables
            where table_type = \"BASE TABLE\"
              and table_schema not in (\"mysql\", \"sys\", \"information_schema\", \"performance_schema\")")
        mariadb -uroot -N -e "$q"' | tr '\t' ' '
fi

# Mounted by a container, not read at the mount point: an NFS volume has one only while used.
image=$(docker images -q restic/restic | head -1)
for v in "$@"; do
    docker volume inspect "$v" >/dev/null 2>&1 || continue
    files=$(docker run --rm --network none --entrypoint sh -v "$v:/v:ro" "${image:-alpine:3.22}" \
        -c 'find /v -type f | wc -l')
    echo "volume $v ${files:-0}"
done
