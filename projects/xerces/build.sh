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

export JAVA_HOME="$OUT/open-jdk-8"
mkdir -p $JAVA_HOME
rsync -aL --exclude=*.zip "/usr/lib/jvm/java-8-openjdk-amd64/" "$JAVA_HOME"

LIBDIR=$SRC/xerces/tools
ANT_HOME="$LIBDIR"
LOCALCLASSPATH="$JAVA_HOME/lib/tools.jar:$JAVA_HOME/lib/classes.zip"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/ant.jar"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/ant-nodeps.jar"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/ant-launcher.jar"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/ant-junit.jar"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/xml-apis.jar"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/xercesImpl.jar"
LOCALCLASSPATH="$LOCALCLASSPATH:$LIBDIR/bin/xjavac.jar"
java -Dant.home="$ANT_HOME" -classpath "$LOCALCLASSPATH" org.apache.tools.ant.Main jars

cp ./build/xercesImpl.jar $OUT/xercesImpl.jar

ALL_JARS="xercesImpl.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.c
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

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
