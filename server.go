// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: APL-2.0

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/tgulacsi/go/text"
	"github.com/timewasted/go-accept-headers"
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
	conn, err := connect(db)
	if err != nil {
		http.Error(w, "bad db "+db, http.StatusNotFound)
		return
	}
	ctx := r.Context()
	var n int64
	table := "mantis_" + path[1] + "_table"
	cols, col := "*", "id"
	if len(path) > 3 && path[3] != "" {
		col = path[3]
		cols = path[3]
	}
	qry := "SELECT COUNT(0) FROM information_schema.columns WHERE table_name = $1 AND column_name = $2"
	if err = conn.QueryRowContext(ctx, qry, table, col).Scan(&n); err != nil {
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
	rows, err := conn.QueryContext(ctx, qry, path[2])
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

func (req queryRequest) Do(ctx context.Context) (*sql.Rows, int64, io.Closer, error) {
	Log := logger.Log
	Log("connecting", req.DB)
	conn, err := connect(req.DB)
	if err != nil {
		Log("msg", "connect", "db", req.DB, "error", err)
		return nil, 0, nil, fmt.Errorf("connecting to %s: %w", req.DB, err)
	}
	defer conn.Close()

	req.Query = strings.TrimSpace(req.Query)
	isSelect := updSecret == "" || len(req.Query) >= 3 && strings.EqualFold(req.Query[:3], "SEL")
	Log("msg", "BEGIN")
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: isSelect})
	if err != nil {
		Log("BEGIN", err)
		return nil, 0, nil, fmt.Errorf("begin: %w", err)
	}
	C := closerFunc(func() error { return tx.Rollback() })

	Log("msg", "prepare", "query", req.Query)
	stmt, err := tx.Prepare(req.Query)
	if err != nil {
		C()
		return nil, 0, nil, fmt.Errorf("prepare: %w", err)
	}
	{
		oldC := C
		C = closerFunc(func() error { err := stmt.Close(); oldC(); return err })
	}

	paramsS := make([]interface{}, len(req.Params))
	for i, s := range req.Params {
		paramsS[i] = interface{}(s)
	}

	if !isSelect {
		if updSecret == "" {
			C()
			return nil, 0, nil, fmt.Errorf("%w: update not allowed (no secret given)", ErrAccessDenied)
		}
		given := req.JWT
		if given == "" {
			C()
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
				if hs := hashStrings(req.Params); mc["params"] != hs && mc["params"] != strings.Join(req.Params, ",") {
					return nil, fmt.Errorf("update params given (%q) is not the same as signed (%q)",
						hs, mc["params"])
				}
				return []byte(updSecret), nil
			})
		if parseErr != nil {
			C()
			return nil, 0, nil, fmt.Errorf("%w: parse jwt token %q: %w", ErrBadRequest, given, parseErr)
		} else if !token.Valid {
			C()
			return nil, 0, nil, fmt.Errorf("update token mismatch: %w", ErrAccessDenied)
		}

		Log("msg", "executing", "update", req.Query, "params", req.Params)
		result, execErr := stmt.ExecContext(ctx, paramsS...)
		if execErr != nil {
			C()
			return nil, 0, nil, fmt.Errorf("update: %w", execErr)
		}
		if err = tx.Commit(); err != nil {
			C()
			return nil, 0, nil, fmt.Errorf("commit: %w", err)
		}
		aff, _ := result.RowsAffected()
		return nil, aff, C, nil
	}

	Log("msg", "executing", "query", req.Query, "params", req.Params)
	rows, err := stmt.QueryContext(ctx, paramsS...)
	if err != nil {
		err = fmt.Errorf("%s: %w", req.Query, err)
	}
	return rows, 0, C, err
}

func (rp requestConfig) writeRows(w io.Writer, rows *sql.Rows, fn string) error {
	if rp.Separator == 0 {
		rp.Separator = ','
	}
	if rp.Charset == "" {
		rp.Charset = "utf-8"
	}
	cols, err := rows.Columns()
	if err != nil {
		return err
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
		if err = cw.Write(cols); err != nil {
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
		if err = rows.Scan(vals...); err != nil {
			Log("msg", "scan", "error", err)
			return err
		}
		for i, pv := range vals {
			v := *(pv.(*interface{}))
			switch x := v.(type) {
			case []byte:
				strs[i] = string(x)
			default:
				strs[i] = fmt.Sprintf("%+v", v)
			}
		}
		if err = cw.Write(strs); err != nil {
			Log("msg", "write", "record", strs, "error", err)
			return err
		}
		n++
	}
	Log("msg", "written", "count", n)
	return rows.Err()
}

type requestConfig struct {
	Separator rune
	Head      bool
	Charset   string
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

func connect(db string) (*sql.DB, error) {
	dbsMtx.RLock()
	conn, ok := dbs[db]
	dbsMtx.RUnlock()
	if ok {
		return conn, nil
	}

	dbsMtx.Lock()
	defer dbsMtx.Unlock()

	dsn := strings.Replace(dsnTemplate, "{{.Name}}", db, 1)
	//logger.Log("msg", "connecting...", "dsn", dsn)
	conn, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	conn.SetMaxIdleConns(1)
	conn.SetMaxOpenConns(10)

	dbs[db] = conn
	return conn, nil
}
