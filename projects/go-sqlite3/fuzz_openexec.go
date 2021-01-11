// Copyright 2021 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE.
// Modified from original file https://github.com/dvyukov/go-fuzz-corpus/blob/master/json/json.go

package sqlite3_fuzz

import (
	"bytes"
	"database/sql"
	"io/ioutil"

	_ "github.com/mattn/go-sqlite3"
)

func FuzzOpenExec(data []byte) int {
	sep := bytes.IndexByte(data, 0)
	if sep <= 0 {
		return 0
	}
	err := ioutil.WriteFile("/tmp/fuzz.db", data[sep+1:], 0644)
	if err != nil {
		return 0
	}
	db, err := sql.Open("sqlite3", "/tmp/fuzz.db")
	if err != nil {
		return 0
	}
	defer db.Close()
	_, err = db.Exec(string(data[:sep-1]))
	if err != nil {
		return 0
	}
	return 1
}
