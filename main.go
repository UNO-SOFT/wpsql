// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: APL-2.0

package main

import (
	"context"
	"encoding/csv"
	"flag"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/UNO-SOFT/ulog"
	"github.com/UNO-SOFT/wpsql/client"

	"github.com/go-kit/kit/log"
	"github.com/peterbourgon/ff/v3/ffcli"
	"gopkg.in/go-on/mannersagain.v1"

	"github.com/tgulacsi/go/globalctx"
)

var logger = log.Logger(ulog.New())

var (
	dsnTemplate string
	updSecret   string
)

func main() {
	if err := Main(); err != nil {
		logger.Log("error", err)
		os.Exit(1)
	}
}

func Main() error {
	var (
		pqUser, pqHost          string
		pqPwEnv, pqUpdSecretEnv string
		pqSSL                   bool
	)
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	flagHTTP := fs.String("http", "0.0.0.0:45432", "address to listen on")
	flagDatabases := fs.String("databases", "", "a comma-separated list of databases to offer")
	flagRestEP := fs.String("rest-endpoint", "/api/v1/mantis/", "REST endpoint")
	serveCmd := ffcli.Command{Name: "serve", FlagSet: fs,
		Exec: func(ctx context.Context, args []string) error {
			var srv server
			for _, nm := range strings.Split(*flagDatabases, ",") {
				if nm != "" {
					srv.Databases = append(srv.Databases, nm)
				}
			}
			http.Handle(*flagRestEP, http.StripPrefix(*flagRestEP, http.HandlerFunc(srv.restHandler)))
			http.HandleFunc("/", srv.queryHandler)
			logger.Log("msg", "serving", "address", *flagHTTP,
				"REST endpoint", *flagRestEP, "databases", srv.Databases)
			return mannersagain.ListenAndServe(*flagHTTP, nil)
		},
	}

	var m client.Client
	fs = flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&m.URL, "server", "http://192.168.1.1:45432", "address of the wpsql server")
	fs.StringVar(&m.DB, "db", "", "database")
	flagClientVerbose := fs.Bool("v", false, "verbose logging")
	clientCmd := ffcli.Command{Name: "client", FlagSet: fs,
		Exec: func(ctx context.Context, args []string) error {
			if *flagClientVerbose {
				m.Log = logger.Log
			}
			qry, params := strings.TrimSpace(args[0]), args[1:]
			m.Secret = os.Getenv(pqUpdSecretEnv)
			if m.Secret != "" && len(qry) > 2 && strings.EqualFold(qry[:3], "UPD") {
				return m.Exec(ctx, qry, params...)
			}
			rows, err := m.Query(ctx, qry, params...)
			if err != nil {
				return err
			}
			cw := csv.NewWriter(os.Stdout)
			return cw.WriteAll(rows)
		},
	}

	fs = flag.NewFlagSet("wpsql", flag.ContinueOnError)
	fs.StringVar(&pqUser, "db-user", "mantis", "username to connect with")
	fs.BoolVar(&pqSSL, "db-ssl", false, "use ssl when connecting to DB?")
	fs.StringVar(&pqPwEnv, "pwenv", "PGPASSW", "name of the environment variable of the user password")
	fs.StringVar(&pqHost, "db-host", "127.0.0.1", "database host")
	fs.StringVar(&pqUpdSecretEnv, "update-secret-env", "UPDATE_SECRET", "name of the environment variable of the secret to update requests")

	app := ffcli.Command{Name: "wpsql", FlagSet: fs,
		Exec: func(ctx context.Context, args []string) error {
			return serveCmd.Exec(ctx, args)
		},
		Subcommands: []*ffcli.Command{&serveCmd, &clientCmd},
	}

	if err := app.Parse(os.Args[1:]); err != nil {
		return err
	}
	updSecret = os.Getenv(pqUpdSecretEnv)

	sslmode := "request"
	if !pqSSL {
		sslmode = "disable"
	}
	dsnTemplate = "postgres://" + url.PathEscape(pqUser) + ":" + url.PathEscape(os.Getenv(pqPwEnv)) + "@" + pqHost + "/{{.Name}}?sslmode=" + sslmode

	ctx, cancel := globalctx.Wrap(context.Background())
	defer cancel()
	return app.Run(ctx)
}

var _ = io.Closer((closerFunc)(nil))

type closerFunc func() error

func (cf closerFunc) Close() error { return cf() }
