#!/bin/bash -eu
# Copyright 2025 Google LLC
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

cat >> gradle.properties << EOF
org.gradle.java.installations.auto-download=false
org.gradle.java.installations.paths=$SRC/graalvm17,$SRC/zulu17
EOF

./gradlew -I $SRC/copy-deps.gradle :core:jar :core:copyRuntimeDeps -PnoLint -PnoWeb --no-daemon

cp core/build/libs/armeria-*.jar $OUT/armeria.jar
rm -rf $OUT/deps
cp -r build/fuzz-deps $OUT/deps

DEPS=$(ls $OUT/deps)
BUILD_CLASSPATH=$JAZZER_API_PATH:$OUT/armeria.jar$(printf ":$OUT/deps/%s" $DEPS)
RUNTIME_CLASSPATH=\$this_dir/armeria.jar$(printf ":\$this_dir/deps/%s" $DEPS):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java')
do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
  # LLVMFuzzerTestOneInput for fuzzer detection.
  this_dir=\$(dirname "\$0")
  if [[ "\$@" =~ (^| )-runs=[0-9]+($| ) ]]
  then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi
  LD_LIBRARY_PATH="$JVM_LD_LIBRARY_PATH":\$this_dir \
    \$this_dir/jazzer_driver                        \
    --agent_path=\$this_dir/jazzer_agent_deploy.jar \
    --cp=$RUNTIME_CLASSPATH                         \
    --target_class=$fuzzer_basename                 \
    --jvm_args="\$mem_settings"                     \
    \$@" > $OUT/$fuzzer_basename

  chmod u+x $OUT/$fuzzer_basename
done
