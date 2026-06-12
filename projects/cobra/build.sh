#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/spf13/cobra
github.com/go-chi/chi/v5 FuzzCobraExecute
FuzzChiRouteMatch fuzz_cobra
