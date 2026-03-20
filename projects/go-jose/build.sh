#!/bin/bash -eu
compile_go_fuzzer github.com/go-jose/go-jose/v4 FuzzJWEDecrypt fuzz_jwe_decrypt
compile_go_fuzzer github.com/go-jose/go-jose/v4 FuzzJWSVerify fuzz_jws_verify
compile_go_fuzzer github.com/go-jose/go-jose/v4 FuzzJWTParse fuzz_jwt_parse
