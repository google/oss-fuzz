#!/bin/bash -eu
go mod download
compile_go_fuzzer github.com/go-playground/validator/v10 FuzzValidatorStruct fuzz_validator
