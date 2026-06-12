#!/bin/bash -eu
go mod download

compile_go_fuzzer github.com/rancher/rancher FuzzSCIMFilterParse fuzz_scim_filter
compile_go_fuzzer github.com/rancher/rancher FuzzGenericMapUnmarshal fuzz_generic_map

