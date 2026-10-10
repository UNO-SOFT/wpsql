// Copyright 2021, 2023 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"unicode"

	"github.com/UNO-SOFT/wpsql/client"
	"github.com/UNO-SOFT/zlog/v2"

	"flag"
	"github.com/UNO-SOFT/cli"
	"github.com/tgulacsi/go/handler"
	"github.com/tgulacsi/go/httpunix"
)

var (
	verbose zlog.VerboseVar = 1
	logger                  = zlog.NewLogger(zlog.MaybeConsoleHandler(&verbose, os.Stderr)).SLog()

	dsnTemplate string
	updSecret   string
)

const DefaultRestEP = "/api/v1/mantis/"

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
		basicAuth, restEP       string
		pqSSL                   bool
	)
	commonFS := flag.NewFlagSet("common", flag.ContinueOnError)
	commonFS.StringVar(&basicAuth, "basic-auth", "", "HTTP Basic authentication (user:passw)")
	commonFS.Var(&verbose, "verbose", "verbosity")

	FS := flag.NewFlagSet("serve", flag.ContinueOnError)
	// FS.SetParent(commonFS)
	FS.StringVar(&pqUser, "db-user", "mantis", "username to connect with")
	FS.BoolVar(&pqSSL, "db-ssl", false, "use ssl when connecting to DB?")
	FS.StringVar(&pqPwEnv, "pwenv", "PGPASSW", "name of the environment variable of the user password")
	FS.StringVar(&pqHost, "db-host", "127.0.0.1", "database host")
	FS.StringVar(&pqUpdSecretEnv, "update-secret-env", "UPDATE_SECRET", "name of the environment variable of the secret to update requests")
	flagHTTP := FS.String("http", "0.0.0.0:45432", "address to listen on")
	flagDatabases := FS.String("databases", "", "a comma-separated list of databases to offer")
	FS.StringVar(&restEP, "rest-endpoint", DefaultRestEP, "REST endpoint")
	flagAliases := FS.String("aliases", "", "alias=db,alias2=db")
	serveCmd := cli.Command{Name: "serve", Flags: FS,
		Exec: func(ctx context.Context, state *cli.State) error {
			var databases []string
			for nm := range strings.SplitSeq(*flagDatabases, ",") {
				if nm != "" {
					databases = append(databases, nm)
				}
			}
			var aliases map[string]string
			if *flagAliases != "" {
				for vv := range strings.FieldsFuncSeq(
					*flagAliases,
					func(r rune) bool { return r == ',' || unicode.IsSpace(r) },
				) {
					if aliases == nil {
						aliases = make(map[string]string, len(aliases))
					}
					k, v, ok := strings.Cut(vv, "=")
					logger.Debug("cut", "vv", vv, "k", k, "v", v, "ok", ok)
					if ok {
						aliases[strings.ToLower(k)] = v
					}
				}
			}
			logger.Debug("aliases", "flag", *flagAliases, "split", aliases)
			srv := newServer(databases, aliases, restEP)

			logger.Info("serving",
				slog.String("address", *flagHTTP),
				slog.String("REST endpoint", restEP),
				slog.String("basicAuth", basicAuth),
				"databases", srv.databases,
				"aliases", srv.aliases,
			)
			hndl := handler.CompressHandler(srv)
			if basicAuth != "" {
				if u, p, ok := strings.Cut(basicAuth, ":"); ok && p != "" {
					logger.Warn("BasicAuth", "u", u, "p", p)
					hndl = handler.BasicAuth(u, p, hndl)
				}
			}
			return httpunix.ListenAndServe(ctx, *flagHTTP, hndl)
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
	FS = flag.NewFlagSet("client", flag.ContinueOnError)
	// FS.SetParent(commonFS)
	FS.StringVar(&m.URL, "server", "http://lnx-web-uno.unosoft.dmz:45432", "address of the wpsql server")
	FS.StringVar(&m.DB, "db", m.DB, "database")
	clientCmd := cli.Command{Name: "client", Flags: FS,
		Exec: func(ctx context.Context, state *cli.State) error {
			args := state.Args
			if verbose != 0 {
				m.Logger = logger
			}
			var err error
			if basicAuth != "" {
				if m.BasicAuth, err = client.SplitBasicAuth(basicAuth); err != nil {
					return fmt.Errorf("SplitBasicAuth: %w", err)
				}
			}
			m.RestEP = restEP
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

	FS = flag.NewFlagSet("wpsql", flag.ContinueOnError)
	// FS.SetParent(commonFS)

	app := cli.Command{Name: "wpsql", Flags: FS,
		Exec: func(ctx context.Context, state *cli.State) error {
			return serveCmd.Exec(ctx, state)
		},
		SubCommands: []*cli.Command{&serveCmd, &clientCmd},
	}

	if err := cli.Parse(&app, os.Args[1:]); err != nil {
		cli.PrintHelp(os.Stderr, &app)
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	updSecret = os.Getenv(pqUpdSecretEnv)
	if restEP == "" {
		restEP = DefaultRestEP
	}

	sslmode := "request"
	if !pqSSL {
		sslmode = "disable"
	}
	dsnTemplate = "postgres://" + url.PathEscape(pqUser) + ":" + url.PathEscape(os.Getenv(pqPwEnv)) + "@" + pqHost + "/{{.Name}}?sslmode=" + sslmode

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	return cli.Run(ctx, &app, nil)
}

var _ = io.Closer((closerFunc)(nil))

type closerFunc func() error

func (cf closerFunc) Close() error { return cf() }
