#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd $GOPATH/src/github.com/mattn/go-sqlite3

compile_go_fuzzer github.com/mattn/go-sqlite3/_example/fuzz FuzzOpenExec fuzz_open_exec

# generate corpus
go run _example/simple/simple.go
echo -n -e "select id, name from foo\x00" > simple.fuzc
cat foo.db >> simple.fuzc
zip -r $OUT/fuzz_open_exec_seed_corpus.zip simple.fuzc
