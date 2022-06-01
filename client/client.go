// Copyright 2021, 2022 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package client implements a client for the PostgreSQL through HTTP wpsql server.
package client

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/UNO-SOFT/wpsql/internal"
	"github.com/dgrijalva/jwt-go"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-logr/logr"
)

// Client is a wpsql client.
// URL must be the URL of the wpsql server.
// DB is the target database.
// Secretus needed for data modification only.
type Client struct {
	logr.Logger
	*http.Client
	URL, DB, Secret string
}

func (m Client) prepareQryWalk(qry string, params []string) url.Values {
	qry, params = m.prepareQry(qry, params)
	values := url.Values(make(map[string][]string, 4))
	values.Set("_head", "0")
	values.Set("_db", m.DB)
	values.Set("_q64", base64.URLEncoding.EncodeToString([]byte(qry)))
	values["_param"] = params
	return values
}

// QueryStringsWalk calls the given callback for each row.
// It quits with the error if the callbacks returns an error.
func (m Client) QueryStringsWalk(ctx context.Context, callback func([]string) error, qry string, params ...string) error {
	resp, err := m.post(ctx, m.prepareQryWalk(qry, params), false)
	if err != nil {
		return err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	tr := &tailReader{Reader: resp.Body}
	cr := csv.NewReader(tr)
	cr.ReuseRecord = false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := cr.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%q: %w", tr.Tail, err)
		}
		if err = callback(record); err != nil {
			return err
		}
	}
}

// QueryWalk calls the given callback for each row.
// It quits with the error if the callbacks returns an error.
func (m Client) QueryWalk(ctx context.Context, callback func([]interface{}) error, qry string, params ...string) error {
	resp, err := m.post(ctx, m.prepareQryWalk(qry, params), true)
	if err != nil {
		return err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	tr := &tailReader{Reader: resp.Body}
	dec := cbor.NewDecoder(tr)
	row := make([]interface{}, strings.Count(resp.Header.Get("Csv-Header"), ","))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := dec.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%q: %w", tr.Tail, err)
		}
		if err := callback(row); err != nil {
			return err
		}
	}
}

// QueryStrings returns the query's results as []string the database.
func (m Client) QueryStrings(ctx context.Context, qry string, params ...string) ([][]string, error) {
	var records [][]string
	err := m.QueryStringsWalk(ctx, func(record []string) error {
		records = append(records, append(make([]string, 0, len(record)), record...))
		return nil
	},
		qry, params...)
	return records, err
}

// Query the database.
func (m Client) Query(ctx context.Context, qry string, params ...string) ([][]interface{}, error) {
	var records [][]interface{}
	err := m.QueryWalk(ctx, func(record []interface{}) error {
		records = append(records, append(make([]interface{}, 0, len(record)), record...))
		return nil
	},
		qry, params...)
	return records, err
}

// Exec a query.
func (m Client) Exec(ctx context.Context, qry string, params ...string) error {
	qry, params = m.prepareQry(qry, params)
	q64 := base64.URLEncoding.EncodeToString([]byte(qry))
	token := jwt.NewWithClaims(jwt.SigningMethodHS512,
		jwt.MapClaims(map[string]interface{}{
			"update": q64,
			"params": internal.HashStrings(params),
			"exp":    time.Now().Add(time.Minute * 1).Unix(),
		}))
	// Set some claims
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte(m.Secret))
	if err != nil {
		m.Error(err, "SignedString", "secret", len(m.Secret))
		return err
	}
	values := url.Values(map[string][]string{
		"_db":    {m.DB},
		"_q64":   {q64},
		"_jwt":   {tokenString},
		"_param": params,
	})
	resp, err := m.post(ctx, values, false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("update %q: %s: %s", values, resp.Status, b)
	}
	return nil
}

func (m Client) post(ctx context.Context, values url.Values, askCBOR bool) (*http.Response, error) {
	m.V(1).Info("post", "values", values)
	vs := values.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", m.URL, strings.NewReader(vs))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if askCBOR {
		req.Header.Set("Accept", "application/cbor")
	}
	cl := m.Client
	if cl == nil {
		cl = http.DefaultClient
	}
	resp, err := cl.Do(req)
	if err != nil {
		m.Error(err, "PostForm")
		if req, err = http.NewRequestWithContext(ctx, "GET", m.URL+"?"+vs, nil); err != nil {
			return nil, err
		}
		resp, err = cl.Do(req)
	}
	if err != nil {
		return nil, fmt.Errorf("%s?%s: %w", m.URL, values.Encode(), err)
	}
	return resp, err
}

func (m Client) prepareQry(qry string, params []string) (string, []string) {
	if len(params) == 0 || !strings.Contains(qry, ":'") {
		return qry, params
	}
	flattened := make([]string, 0, strings.Count(qry, "$"))
	var idx int
	for _, p := range params {
		j := strings.IndexByte(p, '=')
		if j < 0 {
			continue
		}
		k, v := ":'"+p[:j]+"'", p[j+1:]
		for {
			if j = strings.Index(qry, k); j < 0 {
				break
			}
			idx++
			qry = qry[:j] + "$" + strconv.Itoa(idx) + qry[j+len(k):]
			flattened = append(flattened, v)
		}
	}
	m.V(1).Info("prepareQry", "qry", qry)
	return qry, flattened
}

// tailReader is a reader that remembers the last read block.
type tailReader struct {
	io.Reader
	Tail []byte
}

func (tr *tailReader) Read(p []byte) (int, error) {
	n, err := tr.Reader.Read(p)
	if n != 0 {
		tr.Tail = append(tr.Tail[:0], p[:n]...)
	}
	return n, err
}

// vim: set fileencoding=utf-8:
