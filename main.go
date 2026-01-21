// Copyright 2021, 2023 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"unicode"

	"github.com/UNO-SOFT/wpsql/client"
	"github.com/UNO-SOFT/zlog/v2"

	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/tgulacsi/go/handler"
	"gopkg.in/go-on/mannersagain.v1"
)

var verbose zlog.VerboseVar = 1
var logger = zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()

var (
	dsnTemplate string
	updSecret   string
)

func main() {
	if err := Main(); err != nil {
		logger.Error("main", "error", err)
		os.Exit(1)
	}
}

func Main() error {
	var (
		pqUser, pqHost          string
		pqPwEnv, pqUpdSecretEnv string
		pqSSL                   bool
	)
	FS := ff.NewFlagSet("serve")
	flagHTTP := FS.StringLong("http", "0.0.0.0:45432", "address to listen on")
	flagDatabases := FS.StringLong("databases", "", "a comma-separated list of databases to offer")
	flagRestEP := FS.StringLong("rest-endpoint", "/api/v1/mantis/", "REST endpoint")
	flagAliases := FS.StringLong("aliases", "", "alias=db,alias2=db")
	serveCmd := ff.Command{Name: "serve", Flags: FS,
		Exec: func(ctx context.Context, args []string) error {
			var srv server
			for _, nm := range strings.Split(*flagDatabases, ",") {
				if nm != "" {
					srv.Databases = append(srv.Databases, nm)
				}
			}
			aliases := strings.FieldsFunc(*flagAliases, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
			logger.Debug("aliases", "flag", *flagAliases, "split", aliases)
			if len(aliases) != 0 {
				srv.aliases = make(map[string]string, len(aliases))
				for _, vv := range aliases {
					k, v, ok := strings.Cut(vv, "=")
					logger.Debug("cut", "vv", vv, "k", k, "v", v, "ok", ok)
					if ok {
						srv.aliases[strings.ToLower(k)] = v
					}
				}
			}

			http.Handle(*flagRestEP, http.StripPrefix(*flagRestEP, http.HandlerFunc(srv.restHandler)))
			http.HandleFunc("/", srv.queryHandler)
			logger.Info("serving",
				slog.String("address", *flagHTTP),
				slog.String("REST endpoint", *flagRestEP),
				"databases", srv.Databases,
				"aliases", srv.aliases,
			)
			return mannersagain.ListenAndServe(*flagHTTP, handler.CompressHandler(http.DefaultServeMux))
		},
	}

	var m client.Client
	switch x := os.Getenv("BRUNO_CUS"); x {
	case "alf":
		m.DB = "mantis_aegon_prd"
	case "kbe":
		m.DB = "mantis_kobe_prd"
	case "grn", "whb":
		m.DB = "mantis_waberer_prd"
	default:
		if x != "" {
			m.DB = "mantis_" + x + "_prd"
		}
	}
	FS = ff.NewFlagSet("client")
	FS.StringVar(&m.URL, 0, "server", "http://lnx-web-uno.unosoft.dmz:45432", "address of the wpsql server")
	FS.StringVar(&m.DB, 0, "db", m.DB, "database")
	FS.Value('v', "verbose", &verbose, "verbose logging")
	clientCmd := ff.Command{Name: "client", Flags: FS,
		Exec: func(ctx context.Context, args []string) error {
			if verbose != 0 {
				m.Logger = logger
			}
			qry, params := strings.TrimSpace(args[0]), args[1:]
			m.Secret = os.Getenv(pqUpdSecretEnv)
			if m.Secret != "" && len(qry) > 2 && strings.EqualFold(qry[:3], "UPD") {
				return m.Exec(ctx, qry, params...)
			}
			bw := bufio.NewWriter(os.Stdout)
			defer bw.Flush()
			cw := csv.NewWriter(bw)
			return m.QueryStringsWalk(ctx,
				func(record []string) error { return cw.Write(record) },
				qry, params...)
		},
	}

	FS = ff.NewFlagSet("wpsql")
	FS.StringVar(&pqUser, 0, "db-user", "mantis", "username to connect with")
	FS.BoolVar(&pqSSL, 0, "db-ssl", "use ssl when connecting to DB?")
	FS.StringVar(&pqPwEnv, 0, "pwenv", "PGPASSW", "name of the environment variable of the user password")
	FS.StringVar(&pqHost, 0, "db-host", "127.0.0.1", "database host")
	FS.StringVar(&pqUpdSecretEnv, 0, "update-secret-env", "UPDATE_SECRET", "name of the environment variable of the secret to update requests")
	FS.Value('v', "verbose", &verbose, "verbosity")

	app := ff.Command{Name: "wpsql", Flags: FS,
		Exec: func(ctx context.Context, args []string) error {
			return serveCmd.Exec(ctx, args)
		},
		Subcommands: []*ff.Command{&serveCmd, &clientCmd},
	}

	if err := app.Parse(os.Args[1:]); err != nil {
		ffhelp.Command(&app).WriteTo(os.Stderr)
		if errors.Is(err, ff.ErrHelp) {
			return nil
		}
		return err
	}
	updSecret = os.Getenv(pqUpdSecretEnv)

	sslmode := "request"
	if !pqSSL {
		sslmode = "disable"
	}
	dsnTemplate = "postgres://" + url.PathEscape(pqUser) + ":" + url.PathEscape(os.Getenv(pqPwEnv)) + "@" + pqHost + "/{{.Name}}?sslmode=" + sslmode

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return app.Run(ctx)
}

var _ = io.Closer((closerFunc)(nil))

type closerFunc func() error

func (cf closerFunc) Close() error { return cf() }
