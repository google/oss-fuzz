#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/hashicorp/consul FuzzACLTokenUnmarshal fuzz_acl_token
compile_go_fuzzer github.com/hashicorp/consul FuzzACLPolicyUnmarshal fuzz_acl_policy
