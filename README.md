# wpsql - Web PostgreSQL client
## Server
### Install

    go get github.com/UNO-SOFT/wpsql

### Usage

    wpsql [opts] serve [flags]

This starts a server that connects to the allowed databases (`-databases` flag),
on `-db-host` with `-db-user` using the password in the `-pwenv` environment variable.

It allows modifiaction only with the shared secret specified in `-update-secret-env` 
environment variable.

## Client 
There's a library under ./client (`go get github.com/UNO-SOFT/wpsql/client`),
and a simple command line client is usable as

	wpsql client -db=remote_db -server=http://remote_host:port "SELECT * FROM information_schema.tables"
