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

cd $SRC/opentelemetry-collector-contrib/processor/groupbyattrsprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzProcessTraces FuzzProcessTraces_groupbyattrsprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzProcessLogs FuzzProcessLogs_groupbyattrsprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzProcessMetrics FuzzProcessMetrics_groupbyattrsprocessor

cd $SRC/opentelemetry-collector-contrib/processor/logdedupprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzConsumeLogs FuzzConsumeLogs_logdedupprocessor

cd $SRC/opentelemetry-collector-contrib/processor/probabilisticsamplerprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzConsumeTraces FuzzConsumeTraces_probabilisticsamplerprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzConsumeLogs FuzzConsumeLogs__probabilisticsamplerprocessor

cd $SRC/opentelemetry-collector-contrib/processor/sumologicprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzProcessTraces FuzzProcessTraces_sumologicprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzProcessLogs FuzzProcessLogs_sumologicprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzProcessMetrics FuzzProcessMetrics_sumologicprocessor

cd $SRC/opentelemetry-collector-contrib/processor/tailsamplingprocessor
compile_native_go_fuzzer_v2 $(go list) FuzzConsumeTraces FuzzConsumeTraces_tailsamplingprocessor

cd $SRC/opentelemetry-collector-contrib/receiver/lokireceiver/internal
compile_native_go_fuzzer_v2 $(go list) FuzzParseRequest FuzzParseRequest_loki

cd $SRC/opentelemetry-collector-contrib/receiver/mongodbatlasreceiver
compile_native_go_fuzzer_v2 $(go list) FuzzHandleReq FuzzHandleReq_mongodbatlasreceiver

cd $SRC/opentelemetry-collector-contrib/receiver/signalfxreceiver
compile_native_go_fuzzer_v2 $(go list) FuzzHandleDatapointReq FuzzHandleDatapointReq_signalfxreceiver

cd $SRC/opentelemetry-collector-contrib/receiver/splunkhecreceiver
compile_native_go_fuzzer_v2 $(go list) FuzzHandleRawReq FuzzHandleRawReq_splunkhecreceiver

cd $SRC/opentelemetry-collector-contrib/receiver/cloudflarereceiver
compile_native_go_fuzzer_v2 $(go list) FuzzHandleReq FuzzHandleReq_cloudflarereceiver

cd $SRC/opentelemetry-collector-contrib/receiver/webhookeventreceiver
compile_native_go_fuzzer_v2 $(go list) FuzzHandleReq FuzzHandleReq_webhookeventreceiver
