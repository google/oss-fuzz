#!/bin/bash -eu
# Copyright 2023 Google LLC
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
##########################################################################

# Clean up caches
rm -rf $HOME/.gradle/caches/

# Build project and copy dependencies
./gradlew clean :core:jar :core:testClasses :core:copyFuzzDependencies -x test
./gradlew --stop

# Find version
CURRENT_VERSION=$(./gradlew properties | grep ^version: | cut -d" " -f2)

# Copy jars to $OUT
cp core/build/fuzz-dependencies/*.jar $OUT/
cp core/build/libs/avatica-core-$CURRENT_VERSION.jar $OUT/avatica-core.jar
cp metrics/build/libs/avatica-metrics-$CURRENT_VERSION.jar $OUT/avatica-metrics.jar

# Copy fuzzer classes to $OUT (preserving package structure)
cp -r core/build/classes/java/test/* $OUT/

# Create a consolidated list of all jars for the classpath
ALL_JARS=$(find $OUT -maxdepth 1 -name "*.jar" | xargs -n1 basename)

# The runtime classpath will include all jars in $OUT and the this_dir itself for classes
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

# List of fuzzer targets
FUZZERS=(
  "org.apache.calcite.avatica.fuzz.AvaticaSiteFuzzer"
  "org.apache.calcite.avatica.fuzz.JsonHandlerFuzzer"
  "org.apache.calcite.avatica.fuzz.ProtobufHandlerFuzzer"
  "org.apache.calcite.avatica.fuzz.TypedValueFuzzer"
  "org.apache.calcite.avatica.fuzz.Base64Fuzzer"
  "org.apache.calcite.avatica.fuzz.ConnectStringParserFuzzer"
)

# For each fuzzer, create a wrapper script
for target_class in "${FUZZERS[@]}"
do
  fuzzer_basename=$(echo $target_class | awk -F. '{print $NF}')
  
  echo "#!/bin/bash
  # LLVMFuzzerTestOneInput for fuzzer detection.
  this_dir=\$(dirname "\$0")
  if [[ "\$@" =~ (^| )-runs=[0-9]+($| ) ]]
  then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi

  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
    \$this_dir/jazzer_driver                        \
    --agent_path=\$this_dir/jazzer_agent_deploy.jar \
    --cp=$RUNTIME_CLASSPATH                         \
    --target_class=$target_class                 \
    --jvm_args=\"\$mem_settings\"                     \
    \$@" > $OUT/$fuzzer_basename

  chmod u+x $OUT/$fuzzer_basename
done
