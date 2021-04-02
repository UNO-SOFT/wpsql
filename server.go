// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: APL-2.0

package main

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/UNO-SOFT/wpsql/client"
	"github.com/dgrijalva/jwt-go"
	"github.com/tgulacsi/go/text"
	"github.com/timewasted/go-accept-headers"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/kitlogadapter"
	"github.com/jackc/pgx/v4/pgxpool"
)

func (srv server) restHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
		return
	}
	Log := logger.Log
	// /{db}/{table/{id}/{field}?
	path := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 4)
	if len(path) < 3 {
		http.Error(w, fmt.Sprintf("want db/table/id, got %q", path), http.StatusBadRequest)
		return
	}
	rp, err := getReqConfig(r)
	if err != nil {
		Log("rp", rp, "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db := path[0]
	ctx := r.Context()
	conn, err := connect(ctx, db)
	if err != nil {
		http.Error(w, "bad db "+db, http.StatusNotFound)
		return
	}
	defer conn.Release()

	var n int64
	table := "mantis_" + path[1] + "_table"
	cols, col := "*", "id"
	if len(path) > 3 && path[3] != "" {
		col = path[3]
		cols = path[3]
	}
	qry := "SELECT COUNT(0) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2"
	if err = conn.QueryRow(ctx, qry, table, col).Scan(&n); err != nil {
		err = fmt.Errorf("%s: %w", qry, err)
		Log("select", qry, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Error(w, fmt.Sprintf("%q.%q", table, col), http.StatusNotFound)
		return
	}
	qry = fmt.Sprintf("SELECT "+cols+"  FROM %q WHERE id = $1", table) //nolint:gas
	rows, err := conn.Query(ctx, qry, path[2])
	if err != nil {
		err = fmt.Errorf("%s: %w", qry, err)
		Log("select", qry, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if err = rp.writeRows(w, rows, table+".csv"); err != nil {
		Log("msg", "writeRows", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type queryRequest struct {
	DB, JWT, Query string
	Config         requestConfig
	Params         []string
}

var (
	ErrAccessDenied = errors.New("access denied")
	ErrBadRequest   = errors.New("bad request")
)

type server struct {
	Databases []string
}

func (srv server) queryHandler(w http.ResponseWriter, r *http.Request) {
	req := queryRequest{Query: r.FormValue("_q"), JWT: r.Form.Get("_jwt")}
	if req.Query == "" {
		req.Query = r.Form.Get("_query")
	}
	if req.Query == "" {
		if req.Query = r.Form.Get("_q64"); req.Query != "" {
			s, err := base64.URLEncoding.DecodeString(req.Query)
			if err != nil {
				s, err = base64.StdEncoding.DecodeString(req.Query)
			}
			if err != nil {
				logger.Log("msg", "decode", "q", req.Query, "error", err)
			} else {
				req.Query = string(s)
			}
		}
	}
	logger.Log("method", r.Method, "path", r.URL.Path, "qs", r.Form, "query", req.Query)

	if req.Query == "" {
		w.Header().Set("Content-Type", "text/html; charset=\"utf-8\"")
		_, _ = io.WriteString(w, `<!DOCTYPE html>
<html lang="hu"><head>PostgreSQL query</title></head>
<body>
  <form action="" method="POST">
    <p>
      <select name="_db">`+"\n")
		for _, nm := range srv.Databases {
			_, _ = fmt.Fprintf(w, "        <option>%s</option>\n", nm)
		}
		_, _ = io.WriteString(w, `
      </select></p>
	<p><select name="_accept">
	  <option default="1">text/csv;separator=comma</option>
	  <option>text/csv;separator=semicolon</option>
	</select>
	<select name="_charset">
	  <option default="1">utf-8</option>
	  <option>iso-8859-2</option>
    </select>
	</p>
    <p><textarea name="_q" width="80" height="20"></textarea></p>
    <p><input type="submit" value="SELECT" /></p>
  </form>
</body>
</html>`)
		//http.Error(w, "q= is missing", http.StatusBadRequest)
		return
	}

	if len(r.URL.Path) > 1 {
		req.DB = r.URL.Path[1:]
	} else {
		req.DB = r.Form.Get("_db")
	}
	if req.DB == "" {
		http.Error(w, "db= is missing", http.StatusBadRequest)
		return
	}
	if strings.IndexByte(req.DB, '/') >= 0 {
		http.Error(w, fmt.Sprintf("bad db name (%q)", req.DB), http.StatusBadRequest)
		return
	}
	Log := logger.Log
	Log("parsing", r)
	var err error
	if req.Config, err = getReqConfig(r); err != nil {
		Log("msg", "getReqConfig", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var ok bool
	if req.Params, ok = r.Form["_param"]; !ok {
	FormLoop:
		for k, arr := range r.Form {
			if len(k) == 0 {
				continue
			}
			if k[0] == '_' {
				switch k[1:] {
				case "q", "q64", "query", "head", "db", "jwt", "accept", "charset":
					continue FormLoop
				}
			}
			req.Params = append(req.Params, arr...)
		}
	}
	Log("params", req.Params)

	rows, affected, closer, err := req.Do(r.Context())
	if err != nil {
		Log("msg", "doQuery", "req", req, "error", err)
		code := http.StatusInternalServerError
		if errors.Is(err, ErrAccessDenied) {
			code = 401
		} else if errors.Is(err, ErrBadRequest) {
			code = http.StatusBadRequest
		}
		http.Error(w, err.Error(), code)
		return
	}
	defer closer.Close()
	if rows == nil {
		w.Header().Set("Content-Type", `text/csv; charset="`+req.Config.Charset+`"`)
		fmt.Fprintf(w, "%d", affected)
		return
	}
	defer rows.Close()

	if err := req.Config.writeRows(w, rows, "SELECT.csv"); err != nil {
		Log("msg", "writeRows", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (req queryRequest) Do(ctx context.Context) (rows pgx.Rows, affected int64, C io.Closer, err error) {
	Log := logger.Log
	Log("connecting", req.DB)
	conn, connErr := connect(ctx, req.DB)
	if connErr != nil {
		Log("msg", "connect", "db", req.DB, "error", connErr)
		return nil, 0, nil, fmt.Errorf("connecting to %s: %w", req.DB, connErr)
	}
	tbc := append(make([]func() error, 0, 4), func() error { conn.Release(); return nil })
	C = closerFunc(func() error {
		var firstErr error
		for i := len(tbc) - 1; i >= 0; i-- {
			if err := tbc[i](); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	})

	defer func() {
		if err != nil && C != nil {
			C.Close()
		}
	}()

	req.Query = strings.TrimSpace(req.Query)
	accessMode := pgx.ReadOnly
	if updSecret != "" && req.JWT != "" {
		accessMode = pgx.ReadWrite
	}
	Log("msg", "BEGIN")
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: accessMode})
	if err != nil {
		Log("BEGIN", err)
		return nil, 0, nil, fmt.Errorf("begin: %w", err)
	}
	tbc = append(tbc, func() error { return tx.Rollback(context.Background()) })

	paramsS := make([]interface{}, len(req.Params))
	for i, s := range req.Params {
		paramsS[i] = interface{}(s)
	}

	if accessMode != pgx.ReadOnly {
		if updSecret == "" {
			return nil, 0, nil, fmt.Errorf("%w: update not allowed (no secret given)", ErrAccessDenied)
		}
		given := req.JWT
		if given == "" {
			return nil, 0, nil, errors.New("update needs jwt token")
		}

		token, parseErr := jwt.Parse(
			given,
			func(token *jwt.Token) (interface{}, error) {
				// Don't forget to validate the alg is what you expect:
				if sm, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || sm.Alg() != jwt.SigningMethodHS512.Alg() {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				mc, _ := token.Claims.(jwt.MapClaims)
				if mc["update"] != req.Query {
					return nil, fmt.Errorf("update given (%q) is not the same as signed (%q)",
						req.Query, mc["update"])
				}
				if hs := client.HashStrings(req.Params); mc["params"] != hs && mc["params"] != strings.Join(req.Params, ",") {
					return nil, fmt.Errorf("update params given (%q) is not the same as signed (%q)",
						hs, mc["params"])
				}
				return []byte(updSecret), nil
			})
		if parseErr != nil {
			return nil, 0, nil, fmt.Errorf("%v: parse jwt token %q: %w", ErrBadRequest, given, parseErr)
		} else if !token.Valid {
			return nil, 0, nil, fmt.Errorf("update token mismatch: %w", ErrAccessDenied)
		}

		Log("msg", "executing", "update", req.Query, "params", req.Params)
		result, execErr := conn.Exec(ctx, req.Query, paramsS...)
		if execErr != nil {
			return nil, 0, nil, fmt.Errorf("update: %w", execErr)
		}
		if err = tx.Commit(ctx); err != nil {
			return nil, 0, nil, fmt.Errorf("commit: %w", err)
		}
		aff := result.RowsAffected()
		return nil, aff, C, nil
	}

	Log("msg", "executing", "query", req.Query, "params", req.Params)
	if rows, err = conn.Query(ctx, req.Query, paramsS...); err != nil {
		err = fmt.Errorf("%s: %w", req.Query, err)
	}
	return rows, 0, C, err
}

func (rp requestConfig) writeRows(w io.Writer, rows pgx.Rows, fn string) error {
	if rp.Separator == 0 {
		rp.Separator = ','
	}
	if rp.Charset == "" {
		rp.Charset = "utf-8"
	}
	fields := rows.FieldDescriptions()
	cols := make([]string, len(fields))
	for i, f := range fields {
		cols[i] = string(f.Name)
	}
	if rw, ok := w.(http.ResponseWriter); ok {
		rw.Header().Set("Content-Type", `text/csv; charset="`+rp.Charset+`"`)
		rw.Header().Set("Csv-Header", strings.Join(cols, ","))
		rw.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", fn))
	}
	out := io.Writer(w)
	if rp.Charset != "utf-8" {
		tw := text.NewWriter(out, text.GetEncoding(rp.Charset))
		defer tw.Close()
		out = tw
	}
	cw := csv.NewWriter(out)
	cw.Comma = rp.Separator
	defer cw.Flush()
	if rp.Head {
		if err := cw.Write(cols); err != nil {
			return err
		}
	}
	vals := make([]interface{}, len(cols))
	for i := range vals {
		vals[i] = new(interface{})
	}
	strs := make([]string, len(vals))

	Log := logger.Log
	n := 0
	for rows.Next() {
		if err := rows.Scan(vals...); err != nil {
			Log("msg", "scan", "error", err)
			return err
		}
		for i, pv := range vals {
			v := *(pv.(*interface{}))
			if v == nil {
				strs[i] = ""
				continue
			}
			switch x := v.(type) {
			case string:
				strs[i] = x
			case int16, int32, int64, int, uint16, uint32, uint64, uint:
				strs[i] = fmt.Sprintf("%d", x)
			case float64:
				strs[i] = fmt.Sprintf("%f", x)
			case time.Time:
				strs[i] = x.Format(time.RFC3339)
			case pgtype.Timestamp:
				if x.Status != pgtype.Present {
					strs[i] = ""
				} else {
					strs[i] = x.Time.Format(time.RFC3339)
				}
			case pgtype.Date:
				if x.Status != pgtype.Present {
					strs[i] = ""
				} else {
					strs[i] = x.Time.Format(time.RFC3339)
				}
			case pgtype.Numeric:
				if x.Status != pgtype.Present {
					strs[i] = ""
				} else {
					vs, _ := x.Value()
					strs[i] = vs.(string)
				}
			default:
				Log("msg", "Scan", "T", fmt.Sprintf("%T", v), "v", fmt.Sprintf("%#v", v))
				if vr, ok := v.(driver.Valuer); ok {
					var err error
					if v, err = vr.Value(); err != nil {
						return err
					}
				}
				switch x := v.(type) {
				case []byte:
					strs[i] = string(x)
				case string:
					strs[i] = x
				case time.Time:
					strs[i] = x.Format(time.RFC3339)
				case int8, int16, int32, int64, int, uint16, uint32, uint64, uint:
					strs[i] = fmt.Sprintf("%d", v)
				case float32, float64:
					strs[i] = fmt.Sprintf("%f", v)
				case fmt.Stringer:
					strs[i] = x.String()
				default:
					Log("msg", "unknown value", "type", fmt.Sprintf("%T", v), "value", v)
					strs[i] = fmt.Sprintf("%v", v)
				}
			}
		}
		if err := cw.Write(strs); err != nil {
			Log("msg", "write", "record", strs, "error", err)
			return err
		}
		n++
	}
	err := rows.Err()
	Log("msg", "written", "count", n, "error", err)
	return err
}

type requestConfig struct {
	Charset   string
	Separator rune
	Head      bool
}

func getReqConfig(r *http.Request) (requestConfig, error) {
	rp := requestConfig{Separator: ',', Charset: "utf-8"}
	values := r.URL.Query()
	if r.Form != nil {
		values = r.Form
	}
	rp.Head = values.Get("_head") != "0"
	logger.Log("head", rp.Head, "form", values)

	/*
		outType = values.Get("_accept")
		if outType == "" {
			outType = r.Header.Get("Accept")
		}
		if outType != "" {
			accepts := accept.Parse(outType)
		AcceptLoop:
			for _, a := range accepts {
				if a.Extensions != nil {
					switch a.Extensions["separator"] {
					case "":
						continue
					case "comma":
						separator = ','
						break AcceptLoop
					case "semicolon":
						separator = ';'
						break AcceptLoop
					default:
						continue
					}
				}
			}
			if outType, err = accepts.Negotiate("text/csv"); err != nil || outType == "" {
				err = fmt.Errorf("bad Accept=%q: %w",  outType,err)
				return
			}
		}
	*/

	rp.Charset = values.Get("_charset")
	if rp.Charset == "" {
		rp.Charset = r.Header.Get("Accept-Charset")
	}
	var err error
	if rp.Charset == "" {
		rp.Charset = "utf-8"
	} else if rp.Charset, err = accept.Parse(rp.Charset).Negotiate("utf-8", "iso-8859-2"); err != nil || rp.Charset == "" {
		logger.Log("charset", rp.Charset, "error", err)
		if err == nil {
			err = errors.New("unknown")
		}
		return rp, fmt.Errorf("bad charset %q: %w", rp.Charset, err)
	}
	return rp, nil
}

var (
	pgxLogger pgx.Logger
	dbs       = make(map[string]*pgxpool.Pool, 8)
	dbsMtx    sync.RWMutex
)

func connect(ctx context.Context, db string) (*pgxpool.Conn, error) {
	dbsMtx.RLock()
	pool, ok := dbs[db]
	dbsMtx.RUnlock()
	if ok {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		conn, err := pool.Acquire(ctx)
		cancel()
		if err == nil {
			return conn, nil
		}
	}

	dbsMtx.Lock()
	defer dbsMtx.Unlock()

	if pgxLogger == nil {
		pgxLogger = kitlogadapter.NewLogger(logger)
	}

	dsn := strings.Replace(dsnTemplate, "{{.Name}}", db, 1)
	//logger.Log("msg", "connecting...", "dsn", dsn)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Logger = pgxLogger

	if pool, err = pgxpool.ConnectConfig(ctx, cfg); err != nil {
		return nil, err
	}
	dbs[db] = pool
	return pool.Acquire(ctx)
}
