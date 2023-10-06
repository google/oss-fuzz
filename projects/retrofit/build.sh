#!/bin/bash
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

mv $SRC/{*.zip,*.dict} $OUT

export JAVA_HOME="$OUT/open-jdk-11"
mkdir -p $JAVA_HOME
rsync -aL --exclude=*.zip --exclude 'lib/security/blacklisted.certs' "/usr/lib/jvm/java-11-openjdk-amd64/" "$JAVA_HOME"

patch build.gradle build.patch

./gradlew shadowJar

cp $SRC/retrofit/retrofit/build/libs/retrofit-2.10.0-SNAPSHOT-all.jar $OUT/retrofit.jar
cp $SRC/retrofit/samples/build/libs/samples-all.jar $OUT/samples-all.jar
cp $SRC/retrofit/retrofit/test-helpers/build/libs/test-helpers-all.jar $OUT/test-helpers-all.jar

mkdir $OUT/retrofit2

ALL_JARS="retrofit.jar test-helpers-all.jar samples-all.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir:"retrofit2"

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer --release 11
  mv $SRC/[$fuzzer_basename]*.class $OUT/retrofit2

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
JAVA_HOME=\"\$this_dir/open-jdk-11/\" \
LD_LIBRARY_PATH=\"\$this_dir/open-jdk-11/lib/server\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=retrofit2.$fuzzer_basename \
-rss_limit_mb=0 \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done
