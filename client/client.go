// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: APL-2.0

package client

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Client struct {
	URL, DB, Secret string
	Log func(...interface{}) error
	*http.Client
}

func (m Client) Query(ctx context.Context, qry string, params ...string) ([][]string, error) {
	if m.Log != nil {
	m.Log("msg", "Query", "db", m.DB, "q", qry, "params", params)
}
	values := url.Values(make(map[string][]string, 4))
	values.Set("_head", "0")
	values.Set("_db", m.DB)
	values.Set("_q64", base64.URLEncoding.EncodeToString([]byte(qry)))
	values["_param"] = params

	resp, err := m.post(ctx, values)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var buf strings.Builder
	records, err := csv.NewReader(io.TeeReader(resp.Body, &buf)).ReadAll()
	if err != nil {
		return records, fmt.Errorf("%s: %w", buf.String(), err)
	}
	return records, err
}

func HashStrings(params []string) string {
	hsh := sha512.New()
	_ = json.NewEncoder(hsh).Encode(params)
	var a [sha512.Size]byte
	return base64.StdEncoding.EncodeToString(hsh.Sum(a[:0]))
}

func (m Client) Exec(ctx context.Context, qry string, params ...string) error {
	if m.Log != nil {
		m.Log("msg", "Exec", "db", m.DB, "qry", qry, "params", params)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512,
		jwt.MapClaims(map[string]interface{}{
			"update": qry,
			"params": HashStrings(params),
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
		"_q":     {qry},
		"_jwt":   {tokenString},
		"_param": params,
	})
	if m.Log != nil {
		m.Log("msg", "Exec", "values", values)
	}
	resp, err := m.post(ctx, values)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("update %q: %s: %s", values, resp.Status, b)
	}
	return fmt.Errorf("%s: %w", m.URL, err)
}

func (m Client) post(ctx context.Context, values url.Values) (*http.Response, error) {
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

// vim: set fileencoding=utf-8:
