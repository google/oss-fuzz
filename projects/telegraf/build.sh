#/bin/bash -eu
# Copyright 2020 Google Inc.
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

compile_go_fuzzer github.com/influxdata/telegraf/testutil/fuzzing FuzzCsvParser fuzz_csv_parser
compile_go_fuzzer github.com/influxdata/telegraf/testutil/fuzzing FuzzCsvParseLine fuzz_csv_parse_Line
compile_go_fuzzer github.com/influxdata/telegraf/testutil/fuzzing FuzzJSONParse fuzz_json_parse
