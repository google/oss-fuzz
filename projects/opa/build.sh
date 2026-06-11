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
#!/bin/bash -eu
cd $SRC/opa
cp $SRC/fuzz_test.go ast/
compile_go_fuzzer github.com/open-policy-agent/opa/ast FuzzParseModule fuzz_parse_module
compile_go_fuzzer github.com/open-policy-agent/opa/ast FuzzParseBody fuzz_parse_body
compile_go_fuzzer github.com/open-policy-agent/opa/ast FuzzParseExpr fuzz_parse_expr
compile_go_fuzzer github.com/open-policy-agent/opa/ast FuzzParseStatements fuzz_parse_statements
compile_go_fuzzer github.com/open-policy-agent/opa/ast FuzzParseImports fuzz_parse_imports
