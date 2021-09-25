// Copyright 2021 Tamás Gulácsi. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
)

// HashStrings hashes the parameters for JWT authenticity. Used by the server and the client under the hood.
func HashStrings(params []string) string {
	hsh := sha512.New()
	_ = json.NewEncoder(hsh).Encode(params)
	var a [sha512.Size]byte
	return base64.StdEncoding.EncodeToString(hsh.Sum(a[:0]))
}
