#!/bin/bash -eu
# Copyright 2024 Google LLC
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

cd $SRC/go-118-fuzz-build
go build .
mv go-118-fuzz-build /root/go/bin/

cd $SRC/opentelemetry-collector-contrib
cd processor/groupbyattrsprocessor
printf "package groupbyattrsprocessor \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzProcessTraces FuzzProcessTraces_groupbyattrsprocessor
compile_native_go_fuzzer $(go list) FuzzProcessLogs FuzzProcessLogs_groupbyattrsprocessor
compile_native_go_fuzzer $(go list) FuzzProcessMetrics FuzzProcessMetrics_groupbyattrsprocessor

cd ../logdedupprocessor
printf "package logdedupprocessor \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzConsumeLogs FuzzConsumeLogs_logdedupprocessor

cd ../probabilisticsamplerprocessor
printf "package probabilisticsamplerprocessor \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzConsumeTraces FuzzConsumeTraces_probabilisticsamplerprocessor
compile_native_go_fuzzer $(go list) FuzzConsumeLogs FuzzConsumeLogs__probabilisticsamplerprocessor

cd ../sumologicprocessor
printf "package sumologicprocessor \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzProcessTraces FuzzProcessTraces_sumologicprocessor
compile_native_go_fuzzer $(go list) FuzzProcessLogs FuzzProcessLogs_sumologicprocessor
compile_native_go_fuzzer $(go list) FuzzProcessMetrics FuzzProcessMetrics_sumologicprocessor

cd ../tailsamplingprocessor
printf "package tailsamplingprocessor \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzConsumeTraces FuzzConsumeTraces_tailsamplingprocessor

cd ../../receiver/lokireceiver/internal
printf "package internal \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzParseRequest FuzzParseRequest_loki

cd ../../mongodbatlasreceiver
printf "package mongodbatlasreceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzHandleReq FuzzHandleReq_mongodbatlasreceiver

cd ../sapmreceiver
printf "package sapmreceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzParseTraceV2Request FuzzParseTraceV2Request_sapmreceiver

cd ../signalfxreceiver
printf "package signalfxreceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzHandleDatapointReq FuzzHandleDatapointReq_signalfxreceiver

cd ../splunkhecreceiver
printf "package splunkhecreceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzHandleRawReq FuzzHandleRawReq_splunkhecreceiver

cd ../cloudflarereceiver
printf "package cloudflarereceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzHandleReq FuzzHandleReq_cloudflarereceiver

cd ../webhookeventreceiver
printf "package webhookeventreceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer $(go list) FuzzHandleReq FuzzHandleReq_webhookeventreceiver

cd $SRC/opentelemetry-collector
cd receiver/otlpreceiver
printf "package otlpreceiver \nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > ./fuzz-register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer go.opentelemetry.io/collector/receiver/otlpreceiver FuzzReceiverHandlers FuzzReceiverHandlers
cd -

cd pdata
printf "package ptrace\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > $SRC/opentelemetry-collector/pdata/ptrace/register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/plog FuzzUnmarshalJsonLogs FuzzUnmarshalJsonLogs_plogs
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/plog FuzzUnmarshalPBLogs FuzzUnmarshalPBLogs_plogs
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/plog/plogotlp FuzzRequestUnmarshalJSON FuzzRequestUnmarshalJSON_plogotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/plog/plogotlp FuzzResponseUnmarshalJSON FuzzResponseUnmarshalJSON_plogotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/plog/plogotlp FuzzRequestUnmarshalProto FuzzRequestUnmarshalProto_plogotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/plog/plogotlp FuzzResponseUnmarshalProto FuzzResponseUnmarshalProto_plogotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pmetric FuzzUnmarshalMetrics FuzzUnmarshalMetrics_pmetric
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp FuzzRequestUnmarshalJSON FuzzRequestUnmarshalJSON_pmetricotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp FuzzResponseUnmarshalJSON FuzzResponseUnmarshalJSON_pmetricotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp FuzzRequestUnmarshalProto FuzzRequestUnmarshalProto_pmetricotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp FuzzResponseUnmarshalProto FuzzResponseUnmarshalProto_pmetricotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/ptrace FuzzUnmarshalPBTraces FuzzUnmarshalPBTraces_ptrace
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/ptrace FuzzUnmarshalJSONTraces FuzzUnmarshalJSONTraces_ptrace
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp FuzzRequestUnmarshalJSON FuzzRequestUnmarshalJSON_ptraceotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp FuzzResponseUnmarshalJSON FuzzResponseUnmarshalJSON_ptraceotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp FuzzRequestUnmarshalProto FuzzRequestUnmarshalProto_ptraceotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp FuzzResponseUnmarshalProto FuzzResponseUnmarshalProto_ptraceotlp

cd $SRC/opentelemetry-collector/pdata/pprofile
printf "package pprofile\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > register.go
go mod tidy
go mod edit -replace github.com/AdamKorcz/go-118-fuzz-build=$SRC/go-118-fuzz-build
go mod tidy
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp FuzzRequestUnmarshalJSON FuzzRequestUnmarshalJSON_pprofileotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp FuzzResponseUnmarshalJSON FuzzResponseUnmarshalJSON_pprofileotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp FuzzRequestUnmarshalProto FuzzRequestUnmarshalProto_pprofileotlp
compile_native_go_fuzzer go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp FuzzResponseUnmarshalProto FuzzResponseUnmarshalProto_pprofileotlp

cp $SRC/dict $OUT/FuzzUnmarshalJsonLogs_plogs.dict
cp $SRC/dict $OUT/FuzzRequestUnmarshalJSON_pprofileotlp.dict
cp $SRC/dict $OUT/FuzzResponseUnmarshalJSON_pprofileotlp.dict
cp $SRC/dict $OUT/FuzzRequestUnmarshalJSON_plogotlp.dict
cp $SRC/dict $OUT/FuzzResponseUnmarshalJSON_plogotlp.dict
cp $SRC/dict $OUT/FuzzUnmarshalMetrics_pmetric.dict
cp $SRC/dict $OUT/FuzzRequestUnmarshalJSON_pmetricotlp.dict
cp $SRC/dict $OUT/FuzzResponseUnmarshalJSON_pmetricotlp.dict
cp $SRC/dict $OUT/FuzzUnmarshalJSONTraces_ptrace.dict
cp $SRC/dict $OUT/FuzzRequestUnmarshalJSON_ptraceotlp.dict
cp $SRC/dict $OUT/FuzzResponseUnmarshalJSON_ptraceotlp.dict

zip -j $OUT/FuzzUnmarshalJsonLogs_plogs_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzRequestUnmarshalJSON_pprofileotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzResponseUnmarshalJSON_pprofileotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzRequestUnmarshalJSON_plogotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzResponseUnmarshalJSON_plogotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzUnmarshalMetrics_pmetric_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzRequestUnmarshalJSON_pmetricotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzResponseUnmarshalJSON_pmetricotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzUnmarshalJSONTraces_ptrace_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzRequestUnmarshalJSON_ptraceotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*
zip -j $OUT/FuzzResponseUnmarshalJSON_ptraceotlp_seed_corpus.zip $SRC/go-fuzz-corpus/json/corpus/*

