#!/usr/bin/env sh

SQL_SCHEMA=/schema.sql
DB_TABLE=/pdns/pdns_db.sqlite

if [[ ! -f ${DB_TABLE} ]]; then
	sqlite3 /pdns/pdns_db.sqlite < ${SQL_SCHEMA}
	chmod 755 -R /pdns/pdns_db.sqlite
	chown -R pdns:pdns /pdns/pdns_db.sqlite
fi

echo "Starting up PowerDNS"
pdns_server
