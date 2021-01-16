#!/bin/bash -eu
# Copyright 2021 Google Inc.
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


# Change config = ConfigManager()
# to
# config = ConfigManager("/tmp/base.yml")
# 
# The init function of ConfigManager is executed when
# a package that uses the ConfigManager is imported.
# We therefore create /tmp/base.yml at fuzz-time.
sed 's/config = ConfigManager()/config = ConfigManager(defs_file="\/tmp\/base.yml")/g' -i /src/ansible/lib/ansible/constants.py

# Change 'with open(to_bytes(metadata_path))'
# to
# 'with open("/tmp/ansible_builtint_runtime.yml")'
sed 's/to_bytes(metadata_path)/"\/tmp\/ansible_builtin_runtime.yml"/g' -i /src/ansible/lib/ansible/utils/collection_loader/_collection_finder.py

# Change 'args_parser.parse()'
# to
# args_parser.parse(skip_action_validation=True)
sed 's/args_parser.parse()/args_parser.parse(skip_action_validation=True)/g' -i /src/ansible/lib/ansible/playbook/task.py

# Move over config files
export CONFIG_PATH=$SRC/ansible/lib/ansible/config
cp $SRC/base_yml.py $CONFIG_PATH/
cp $SRC/ansible_builtin_runtime_yml.py $CONFIG_PATH/

pip3 install .
pip3 freeze


# Build fuzzers

for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Create execution wrapper.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_PRELOAD=\$this_dir/sanitizer_with_fuzzer.so \
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
