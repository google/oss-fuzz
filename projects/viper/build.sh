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

cd $SRC/viper
cp $SRC/fuzz_test.go ./
compile_go_fuzzer github.com/spf13/viper FuzzReadConfig fuzz_read_config
compile_go_fuzzer github.com/spf13/viper FuzzUnmarshal fuzz_unmarshal
compile_go_fuzzer github.com/spf13/viper FuzzMergeConfigMap fuzz_merge_config_map
compile_go_fuzzer github.com/spf13/viper FuzzSetGet fuzz_set_get
compile_go_fuzzer github.com/spf13/viper FuzzConfigFile fuzz_config_file

