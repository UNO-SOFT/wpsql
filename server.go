// Copyright 2021, 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/UNO-SOFT/wpsql/internal"
	"github.com/dgrijalva/jwt-go"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-logr/logr"
	"github.com/tgulacsi/go/text"
	"github.com/timewasted/go-accept-headers"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/tracelog"
)

func (srv server) restHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
		return
	}
	// /{db}/{table/{id}/{field}?
	path := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 4)
	if len(path) < 3 {
		http.Error(w, fmt.Sprintf("want db/table/id, got %q", path), http.StatusBadRequest)
		return
	}
	rp, err := getReqConfig(r)
	if err != nil {
		logger.Error(err, "getReqConfig", "rp", rp)
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
		logger.Error(err, "select", qry, "table", table, "col", col)
		err = fmt.Errorf("%s: %w", qry, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n == 0 {
		http.Error(w, fmt.Sprintf("%q.%q", table, col), http.StatusNotFound)
		return
	}
	// nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
	qry = "SELECT " + cols + "  FROM " + strconv.Quote(table) + " WHERE id = $1" //nolint:gas
	rows, err := conn.Query(ctx, qry, path[2])
	if err != nil {
		logger.Error(err, "select", qry, "path", path[2])
		err = fmt.Errorf("%s: %w", qry, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if err = rp.writeRows(w, rows, table+".csv"); err != nil {
		logger.Error(err, "writeRows")
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
				logger.Error(err, "decode", "q", req.Query)
			} else {
				req.Query = string(s)
			}
		}
	}
	logger.Info("queryHandler", "method", r.Method, "path", r.URL.Path, "qs", r.Form, "query", req.Query)

	if req.Query == "" {
		w.Header().Set("Content-Type", "text/html; charset=\"utf-8\"")
		_, _ = io.WriteString(w, `<!DOCTYPE html>
<html lang="hu"><head>PostgreSQL query</title></head>
<body>
  <form action="" method="POST">
    <p>
      <select name="_db">`+"\n")
		for _, nm := range srv.Databases {
			// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
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
	logger.V(1).Info("parsing", "request", r)
	config, err := getReqConfig(r)
	if err != nil {
		logger.Error(err, "getReqConfig")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Config = config
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
	logger.V(1).Info("req.Params", "params", req.Params)

	rows, affected, closer, err := req.Do(r.Context())
	if err != nil {
		logger.Error(err, "doQuery", "req", req)
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
		// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
		fmt.Fprintf(w, "%d", affected)
		return
	}
	defer rows.Close()

	if err := req.Config.writeRows(w, rows, "SELECT.csv"); err != nil {
		logger.Error(err, "writeRows")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (req queryRequest) Do(ctx context.Context) (rows pgx.Rows, affected int64, C io.Closer, err error) {
	logger.V(1).Info("connecting", "db", req.DB)
	conn, connErr := connect(ctx, req.DB)
	if connErr != nil {
		logger.Error(connErr, "connect", "db", req.DB)
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
	logger.V(1).Info("BEGIN")
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: accessMode})
	if err != nil {
		logger.Error(err, "BEGIN")
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
				if upd, ok := mc["update"].(string); !(ok && upd == req.Query) {
					if upd, err := base64.URLEncoding.DecodeString(upd); !(err == nil && string(upd) == req.Query) {
						return nil, fmt.Errorf("update given (%q) is not the same as signed (%q)",
							req.Query, mc["update"])
					}
				}
				if hs := internal.HashStrings(req.Params); mc["params"] != hs && mc["params"] != strings.Join(req.Params, ",") {
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

		logger.Info("executing", "update", req.Query, "params", req.Params)
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

	logger.Info("executing", "query", req.Query, "params", req.Params)
	if rows, err = conn.Query(ctx, req.Query, paramsS...); err != nil {
		err = fmt.Errorf("%s: %w", req.Query, err)
	}
	return rows, 0, C, err
}

const utf8 = "utf-8"

type codec struct{ Name string }

var (
	CodecCSV  = codec{"csv"}
	CodecCBOR = codec{"cbor"}
	CodecJSON = codec{"json"}
)

func (rp requestConfig) writeRows(w io.Writer, rows pgx.Rows, fn string) error {
	if rp.Charset == "" {
		rp.Charset = utf8
	}
	if rp.Separator == 0 {
		rp.Separator = ','
	}

	fields := rows.FieldDescriptions()
	cols := make([]string, len(fields))
	for i, f := range fields {
		cols[i] = string(f.Name)
	}
	ct := rp.Codec.Name
	if rw, ok := w.(http.ResponseWriter); ok {
		switch rp.Codec {
		case CodecCSV:
			ct = `text/csv; charset="` + rp.Charset + `"`
		case CodecJSON, CodecCBOR:
			ct = "application/" + rp.Codec.Name
		}
		rw.Header().Set("Content-Type", ct)
		rw.Header().Set("Csv-Header", strings.Join(cols, ","))
		rw.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", fn))
	}
	logger.Info("writeRows", "contentType", ct)
	vals := make([]interface{}, len(cols))
	for i := range vals {
		vals[i] = new(interface{})
	}

	var addCol func(i int, v interface{}) error
	var writeRow func() error
	switch rp.Codec {
	case CodecCSV:
		out := w
		if rp.Charset != utf8 {
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
		strs := make([]string, len(vals))
		writeRow = func() error {
			if err := cw.Write(strs); err != nil {
				return fmt.Errorf("write row %q: %w", strs, err)
			}
			return nil
		}
		addCol = func(i int, v interface{}) error {
			if v == nil {
				strs[i] = ""
				return nil
			}
			switch x := v.(type) {
			case bool:
				if x {
					strs[i] = "t"
				} else {
					strs[i] = "f"
				}
			case string:
				strs[i] = x
			case int16, int32, int64, int, uint16, uint32, uint64, uint:
				strs[i] = fmt.Sprintf("%d", x)
			case float64:
				strs[i] = fmt.Sprintf("%f", x)
			case time.Time:
				strs[i] = x.Format(time.RFC3339)
			case pgtype.Timestamp:
				if !x.Valid {
					strs[i] = ""
				} else {
					strs[i] = x.Time.Format(time.RFC3339)
				}
			case pgtype.Date:
				if !x.Valid {
					strs[i] = ""
				} else {
					strs[i] = x.Time.Format(time.RFC3339)
				}
			case pgtype.Numeric:
				if !x.Valid {
					strs[i] = ""
				} else {
					vs, _ := x.Value()
					strs[i] = vs.(string)
				}
			default:
				logger.Info("Scan", "T", fmt.Sprintf("%T", v), "v", fmt.Sprintf("%#v", v))
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
					logger.Info("unknown value", "type", fmt.Sprintf("%T", v), "value", v)
					strs[i] = fmt.Sprintf("%v", v)
				}
			}
			return nil
		}

	case CodecCBOR, CodecJSON:
		var enc interface{ Encode(interface{}) error }
		switch rp.Codec {
		case CodecCBOR:
			enc = cbor.NewEncoder(w)
		case CodecJSON:
			enc = json.NewEncoder(w)
		}
		if rp.Head {
			if err := enc.Encode(cols); err != nil {
				return err
			}
		}
		row := make([]interface{}, len(cols))
		addCol = func(i int, v interface{}) error {
			row[i] = nil
			switch x := v.(type) {
			case pgtype.Bool:
				if x.Valid {
					row[i] = x.Bool
				}
			case pgtype.Float4:
				if x.Valid {
					row[i] = x.Float32
				}
			case pgtype.Float8:
				if x.Valid {
					row[i] = x.Float64
				}
			case pgtype.Int2:
				if x.Valid {
					row[i] = x.Int16
				}
			case pgtype.Int4:
				if x.Valid {
					row[i] = x.Int32
				}
			case pgtype.Int8:
				if x.Valid {
					row[i] = x.Int64
				}
			case pgtype.Timestamp:
				if x.Valid {
					row[i] = x.Time
				}
			case pgtype.Date:
				if x.Valid {
					row[i] = x.Time
				}
			case pgtype.Numeric:
				if x.Valid {
					vs, _ := x.Value()
					row[i] = vs.(string)
				}
			default:
				row[i] = v
			}
			return nil
		}
		writeRow = func() error {
			if err := enc.Encode(row); err != nil {
				return fmt.Errorf("encode %v: %w", row, err)
			}
			return nil
		}

	default:
		return fmt.Errorf("%q: %w", rp.Codec, ErrUnknownCodec)
	}

	n := 0
	for rows.Next() {
		if err := rows.Scan(vals...); err != nil {
			logger.Error(err, "scan", "vals", vals)
			return err
		}
		for i, pv := range vals {
			v := *(pv.(*interface{}))
			if err := addCol(i, v); err != nil {
				logger.Error(err, "addCol", "i", i, "value", v)
				return err
			}
		}
		if err := writeRow(); err != nil {
			logger.Error(err, "write")
			return err
		}
		n++
	}
	err := rows.Err()
	logger.Info("written", "count", n, "error", err)
	return err
}

type requestConfig struct {
	Charset   string
	Codec     codec
	Separator rune
	Head      bool
}

var ErrUnknownCodec = errors.New("unknown codec")

func getReqConfig(r *http.Request) (requestConfig, error) {
	rp := requestConfig{Separator: ',', Charset: utf8}
	values := r.URL.Query()
	if r.Form != nil {
		values = r.Form
	}
	rp.Head = values.Get("_head") != "0"
	logger.V(1).Info("getReqConfig", "head", rp.Head, "form", values)

	outType := values.Get("_accept")
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
					rp.Separator = ','
					break AcceptLoop
				case "semicolon":
					rp.Separator = ';'
					break AcceptLoop
				default:
					continue
				}
			}
		}
		var err error
		if outType, err = accepts.Negotiate("text/csv", "application/cbor", "application/json"); err != nil || outType == "" {
			return rp, fmt.Errorf("bad Accept=%q: %w", outType, err)
		}
	}
	if outType == "" {
		outType = "text/csv"
	}

	switch outType {
	case "text/csv":
		rp.Codec = CodecCSV
		rp.Charset = values.Get("_charset")
		if rp.Charset == "" {
			rp.Charset = r.Header.Get("Accept-Charset")
		}
		if rp.Charset == "" {
			rp.Charset = "utf-8"
		} else if cs, err := accept.Parse(rp.Charset).Negotiate("utf-8", "iso-8859-2"); err == nil && cs != "" {
			rp.Charset = cs
		} else {
			logger.Error(err, "parse accept", "charset", rp.Charset)
			if err == nil {
				err = errors.New("unknown")
			}
			return rp, fmt.Errorf("bad charset %q: %w", rp.Charset, err)
		}

	case "application/cbor":
		rp.Codec = CodecCBOR

	case "application/json":
		rp.Codec = CodecJSON

	default:
		return rp, fmt.Errorf("%q: %w", outType, ErrUnknownCodec)
	}
	return rp, nil
}

var (
	dbs    = make(map[string]*pgxpool.Pool, 8)
	dbsMtx sync.RWMutex
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

	dsn := strings.Replace(dsnTemplate, "{{.Name}}", db, 1)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger:   pgxLogger{Logger: logger.AsLogr().V(1)},
		LogLevel: tracelog.LogLevelInfo,
	}

	if pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		return nil, err
	}
	dbs[db] = pool
	return pool.Acquire(ctx)
}

var _ tracelog.Logger = pgxLogger{}

type pgxLogger struct{ logr.Logger }

func (p pgxLogger) Log(ctx context.Context, level tracelog.LogLevel, msg string, data map[string]interface{}) {
	keyvals := make([]interface{}, 0, len(data))
	for k, v := range data {
		keyvals = append(keyvals, k, v)
	}
	p.Logger.V(int(level)-3).Info(msg, keyvals...)
}
