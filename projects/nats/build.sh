#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/nats-io/nats-server/v2 FuzzParseCertStore fuzz_cert_store
compile_go_fuzzer github.com/nats-io/nats-server/v2 FuzzParseCertMatchBy fuzz_cert_match


