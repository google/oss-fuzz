#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/go-chi/chi/v5 FuzzChiRouteMatch fuzz_chi
