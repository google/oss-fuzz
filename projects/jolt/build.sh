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
################################################################################

export TARGET_PACKAGE_PREFIX="com.bazaarvoice.jolt."

MAVEN_ARGS="-Dmaven.test.skip=true -Djavac.src.version=15 -Djavac.target.version=15 --update-snapshots"
$MVN clean -pl "!cli,!guice" package $MAVEN_ARGS

BUILD_CLASSPATH=
RUNTIME_CLASSPATH=

for JARFILE in $(find ./ -name *.jar)
do
  cp $JARFILE $OUT/
  BUILD_CLASSPATH=$BUILD_CLASSPATH$OUT/$(basename $JARFILE):
  RUNTIME_CLASSPATH=$RUNTIME_CLASSPATH\$this_dir/$(basename $JARFILE):
done

# Retrieve apache-common-lang3 library
# This library provides method to translate primitive type arrays to
# their respective class object arrays to avoid compilation error.
wget -P $OUT/ https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar
wget -P $OUT/ https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.15.2/jackson-databind-2.15.2.jar
wget -P $OUT/ https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.15.2/jackson-core-2.15.2.jar
wget -P $OUT/ https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.15.2/jackson-annotations-2.15.2.jar

BUILD_CLASSPATH=$BUILD_CLASSPATH:$JAZZER_API_PATH:$OUT/commons-lang3-3.12.0.jar:$OUT/jackson-databind-2.15.2.jar:$OUT/jackson-core-2.15.2.jar:$OUT/jackson-annotations-2.15.2.jar
RUNTIME_CLASSPATH=$RUNTIME_CLASSPATH:\$this_dir/commons-lang3-3.12.0.jar:\$this_dir/jackson-databind-2.15.2.jar:\$this_dir/jackson-core-2.15.2.jar:\$this_dir/jackson-annotations-2.15.2.jar:\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
