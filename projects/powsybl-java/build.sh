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

# Build powsybl-core
pushd powsybl-core
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Build powsybl-diagram
pushd powsybl-diagram
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Build powsybl-metrix
pushd powsybl-metrix
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Build powsybl-open-rao
pushd powsybl-open-rao
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Build powsybl-dynawo
pushd powsybl-dynawo
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Build powsybl-open-loadflow
pushd powsybl-open-loadflow
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Build powsybl-entsoe
pushd powsybl-entsoe
$MVN clean package -DskipTests=true -Dmaven.javadoc.skip=true
popd

# Disable logging
echo "<configuration><root level=\"OFF\" /></configuration>" > $OUT/logback.xml

ALL_JARS=
ALL_DEP_JARS=
mkdir -p $OUT/dependencies
for jar in $(find ./powsybl* -type f -name "*.jar")
do
  if [[ "$jar" != *"target/powsybl/share"* ]]
  then
    if [[ "$jar" != *"powsybl"* ]]
    then
      ALL_DEP_JARS=$ALL_DEP_JARS"$(basename $jar) "
      cp "$jar" $OUT/dependencies
    elif [[ "$jar" != *"test"* ]]
    then
      ALL_JARS=$ALL_JARS"$(basename $jar) "
      cp "$jar" $OUT
    fi
  else
    ALL_DEP_JARS=$ALL_DEP_JARS"$(basename $jar) "
    cp "$jar" $OUT/dependencies
  fi
done

# Download extra needed dependencies jar
wget https://repo1.maven.org/maven2/com/google/jimfs/jimfs/1.3.0/jimfs-1.3.0.jar
ALL_DEP_JARS=$ALL_DEP_JARS"jimfs-1.3.0.jar"
cp jimfs-1.3.0.jar $OUT/dependencies

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):$(echo $ALL_DEP_JARS | xargs printf -- "\$this_dir/dependencies/%s:"):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
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


mkdir -p $SRC/LoadFlowFuzzer-seeds
find $SRC -name '*.uct' -exec cp "{}" $SRC/LoadFlowFuzzer-seeds/  \;
find $SRC -name '*.dgs' -exec cp "{}" $SRC/LoadFlowFuzzer-seeds/  \;
find $SRC -name '*.json' -exec cp "{}" $SRC/LoadFlowFuzzer-seeds/  \;
find $SRC -name '*.raw' -exec cp "{}" $SRC/LoadFlowFuzzer-seeds/  \;

mkdir -p $SRC/DeserializeFuzzer-seeds
find $SRC -name '*.json' -exec cp "{}" $SRC/DeserializeFuzzer-seeds/  \;

mkdir -p $SRC/ParseFuzzer-seeds
find $SRC -name '*.json' -exec cp "{}" $SRC/ParseFuzzer-seeds/  \;

pushd $SRC/LoadFlowFuzzer-seeds
zip $OUT/LoadFlowFuzzer_seed_corpus.zip ./*
popd

pushd $SRC/DeserializeFuzzer-seeds
zip $OUT/DeserializeFuzzer_seed_corpus.zip ./*
popd

pushd $SRC/ParseFuzzer-seeds
zip $OUT/ParseFuzzer_seed_corpus.zip ./*
popd

pushd $SRC/powsybl-seed-corpus/MatrixFuzzer_seed_corpus
zip $OUT/MatrixFuzzer_seed_corpus.zip ./*
popd

wget -O $SRC/json.dict https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/json.dict
cp $SRC/json.dict $OUT/LoadFlowFuzzer.dict
cp $SRC/json.dict $OUT/DeserializeFuzzer.dict
cp $SRC/json.dict $OUT/ParseFuzzer.dict
