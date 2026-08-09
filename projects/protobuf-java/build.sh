#!/bin/bash -eu
# Copyright 2021 Google LLC
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

# Get the latest stable protobuf-java version from Maven Central
unset CFLAGS CXXFLAGS
JAVA_VERSION=$(curl --silent "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/maven-metadata.xml" \
  | grep '<version>4\.' | grep -v RC | grep -v alpha | grep -v beta | tail -1 | sed 's/.*<version>//;s/<.*//' | tr -d '[:space:]')
# Derive the protoc version from the Java version (strip the leading "4.")
VERSION=${JAVA_VERSION#4.}

mkdir -p $SRC/protobuf
PROTOC_ZIP="protoc-$VERSION-linux-x86_64.zip"
curl --silent --fail -L -o "$SRC/$PROTOC_ZIP" "https://github.com/protocolbuffers/protobuf/releases/download/v$VERSION/$PROTOC_ZIP"
unzip -o $PROTOC_ZIP -d $SRC/protobuf
export PROTOC=$SRC/protobuf/bin/protoc

# Download matching protobuf-java jar
JAR_FILE="protobuf-java-$JAVA_VERSION.jar"
curl --silent --fail -L -o "$SRC/$JAR_FILE" "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/$JAVA_VERSION/$JAR_FILE"
cp "$SRC/$JAR_FILE" $OUT/protobuf-java.jar

# Compile test protos with protoc.
cd $SRC/
$PROTOC --java_out=. --proto_path=. test-full.proto
jar --create --file $OUT/test-full.jar foo/*

ALL_JARS="protobuf-java.jar test-full.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
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
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\" \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done

