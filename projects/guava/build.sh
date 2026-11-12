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

MAVEN_ARGS="-Djavac.src.version=15 -Djavac.target.version=15 -DskipTests"
$MVN install $MAVEN_ARGS
CURRENT_VERSION=$($MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
 -Dexpression=project.version -q -DforceStdout)
cp "guava/target/guava-$CURRENT_VERSION.jar" "$OUT/guava.jar"

# Build the Android flavor from the same checkout. Existing targets continue to use the JRE jar.
$MVN -f android/pom.xml -pl guava -am $MAVEN_ARGS \
  -Dcheckstyle.skip=true -Drat.skip=true -Dmaven.javadoc.skip=true \
  -Danimal.sniffer.skip=true package
mapfile -t ANDROID_JARS < <(
  find android/guava/target -maxdepth 1 -type f -name 'guava-*.jar' \
    ! -name '*-sources.jar' ! -name '*-javadoc.jar' ! -name '*-tests.jar' | sort
)
[[ ${#ANDROID_JARS[@]} -eq 1 ]] || {
  printf 'Expected exactly one Android Guava jar, found %s: %s\n' \
    "${#ANDROID_JARS[@]}" "${ANDROID_JARS[*]-}" >&2
  exit 1
}
cp "${ANDROID_JARS[0]}" "$OUT/guava-android.jar"

ALL_JARS="guava.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir
ANDROID_RUNTIME_CLASSPATH="\$this_dir/guava-android.jar:\$this_dir"
mapfile -t JRE_FUZZERS < <(
  find "$SRC" -maxdepth 1 -type f -name '*Fuzzer.java' \
    ! -name 'AndroidImmutableCollectionsHashFloodingFuzzer.java' | sort
)
javac -cp "$BUILD_CLASSPATH" "${JRE_FUZZERS[@]}"
javac -cp "$OUT/guava-android.jar:$JAZZER_API_PATH" \
  "$SRC/AndroidImmutableCollectionsHashFloodingFuzzer.java"
install ${SRC}/*.class ${OUT}/

for fuzzer in $(find $SRC -name '*Fuzzer.java' -maxdepth 1); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  target_classpath=$RUNTIME_CLASSPATH
  if [[ $fuzzer_basename == AndroidImmutableCollectionsHashFloodingFuzzer ]]; then
    target_classpath=$ANDROID_RUNTIME_CLASSPATH
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
--cp=$target_classpath \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
