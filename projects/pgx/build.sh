# Copyright 2026 Google LLC
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

cd $SRC/pgx
cp $SRC/fuzz_test.go ./
compile_go_fuzzer github.com/jackc/pgx/v5 FuzzParseConfig fuzz_parse_config
compile_go_fuzzer github.com/jackc/pgx/v5 FuzzConnString fuzz_conn_string
compile_go_fuzzer github.com/jackc/pgx/v5 FuzzConnConfig fuzz_conn_config
compile_go_fuzzer github.com/jackc/pgx/v5 FuzzRuntimeParams fuzz_runtime_params
compile_go_fuzzer github.com/jackc/pgx/v5 FuzzScanRow fuzz_scan_row

