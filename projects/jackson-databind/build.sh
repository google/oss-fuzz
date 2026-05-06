#!/bin/bash -eu
# Copyright 2022 Google LLC
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

cd $SRC/jackson-databind

# Move seed corpus and dictionary.
mv $SRC/{*.zip,*.dict} $OUT
mv $SRC/github-samples/jackson/*.zip $OUT/

# jackson-annotations (must be built first - no dependencies)
MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 -DskipTests"
$MVN package $MAVEN_ARGS -f "jackson-annotations/pom.xml"
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout -f "jackson-annotations/pom.xml")
cp "jackson-annotations/target/jackson-annotations-$CURRENT_VERSION.jar" "$OUT/jackson-annotations.jar"

# jackson-core (depends on jackson-annotations)
MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 -DskipTests"
$MVN package $MAVEN_ARGS -f "jackson-core/pom.xml"
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout -f "jackson-core/pom.xml")
cp "jackson-core/target/jackson-core-$CURRENT_VERSION.jar" "$OUT/jackson-core.jar"

# jackson-databind (depends on both jackson-core and jackson-annotations)
MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 -DskipTests"
$MVN package $MAVEN_ARGS
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)
cp "target/jackson-databind-$CURRENT_VERSION.jar" "$OUT/jackson-databind.jar"

ALL_JARS="jackson-databind.jar jackson-core.jar jackson-annotations.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  cp $SRC/$fuzzer_basename\$DummyClass.class $OUT/ 2>/dev/null || true
  if [ "$fuzzer_basename" == "AdaLObjectReader3Fuzzer" ]; then
    cp $SRC/$fuzzer_basename\$NoCheckSubTypeValidator.class $OUT/
    cp $SRC/$fuzzer_basename\$MockFuzzDataInput.class $OUT/
  fi

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
--instrumentation_excludes=tools.jackson.core.** \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
