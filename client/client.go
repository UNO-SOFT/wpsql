// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: APL-2.0

// Package client implements a client for the PostgreSQL through HTTP wpsql server.
package client

import (
	"context"
	"encoding/base64"
	"encoding/csv"
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
)

// Client is a wpsql client.
// URL must be the URL of the wpsql server.
// DB is the target database.
// Secretus needed for data modification only.
type Client struct {
	Log func(...interface{}) error
	*http.Client
	URL, DB, Secret string
}

// Query the database.
func (m Client) Query(ctx context.Context, qry string, params ...string) ([][]string, error) {
	qry, params = m.prepareQry(qry, params)
	values := url.Values(make(map[string][]string, 4))
	values.Set("_head", "0")
	values.Set("_db", m.DB)
	values.Set("_q64", base64.URLEncoding.EncodeToString([]byte(qry)))
	values["_param"] = params

	resp, err := m.post(ctx, values)
	if err != nil {
		return nil, err
	}

	if resp.Body != nil {
		defer resp.Body.Close()
	}

	var buf strings.Builder
	records, err := csv.NewReader(io.TeeReader(resp.Body, &buf)).ReadAll()
	if err != nil {
		return records, fmt.Errorf("%s: %w", buf.String(), err)
	}
	return records, nil
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
		if m.Log != nil {
			m.Log("msg", "SignedString", "secret", len(m.Secret), "error", err)
		}
		return err
	}
	values := url.Values(map[string][]string{
		"_db":    {m.DB},
		"_q64":   {q64},
		"_jwt":   {tokenString},
		"_param": params,
	})
	resp, err := m.post(ctx, values)
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

func (m Client) post(ctx context.Context, values url.Values) (*http.Response, error) {
	if m.Log != nil {
		m.Log("msg", "post", "values", values)
	}
	vs := values.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", m.URL, strings.NewReader(vs))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cl := m.Client
	if cl == nil {
		cl = http.DefaultClient
	}
	resp, err := cl.Do(req)
	if err != nil {
		if m.Log != nil {
			m.Log("msg", "PostForm", "error", err)
		}
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
	if m.Log != nil {
		m.Log("qry", qry)
	}
	return qry, flattened
}

// vim: set fileencoding=utf-8:
