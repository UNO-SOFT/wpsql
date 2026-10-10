module github.com/UNO-SOFT/wpsql

go 1.27.0

require (
	github.com/UNO-SOFT/cli v0.0.0-20261009074406-95b18dbd4953
	github.com/UNO-SOFT/zlog v0.8.6
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/fxamacker/cbor/v2 v2.9.6
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3
	github.com/jackc/pgx/v5 v5.11.0
	github.com/peterbourgon/ff/v4 v4.0.0-beta.1
	github.com/tgulacsi/go v0.30.0
	github.com/timewasted/go-accept-headers v0.0.0-20130320203746-c78f304b1b09
)

require (
	github.com/dgryski/go-linebreak v0.0.0-20180812204043-d8f37254e7d3 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/exp v0.0.0-20261009195045-ca0d7ba23607 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/term v0.47.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/peterbourgon/ff/v4 v4.0.0-beta.1 => github.com/UNO-SOFT/ff/v4 v4.0.0-beta.1.us
