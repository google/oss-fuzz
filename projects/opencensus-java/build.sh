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

PROJECT=opencensus-java
PROJECT_GROUP_ID=io.opencensus
PROJECT_ARTIFACT_ID=opencensus-api
MAIN_REPOSITORY=https://github.com/census-instrumentation/opencensus-java/
MAVEN_ARGS="-Djavac.src.version=1.8 -Djavac.target.version=1.8 -Denforcer.skip=true -DskipTests"
GRADLE_ARGS="-x javadoc -x test"

function set_project_version_in_fuzz_targets_dependency {
  PROJECT_VERSION=$(cd $PROJECT && $MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.version -q -DforceStdout)
  # set dependency project version in fuzz-targets
  (cd fuzz-targets && $MVN versions:use-dep-version -Dincludes=$PROJECT_GROUP_ID:$PROJECT_ARTIFACT_ID -DdepVersion=$PROJECT_VERSION -DforceVersion=true)
}

cd project-parent

pushd $PROJECT
  export OPENCENSUS_JAVA_VERSION=$(awk '$1 ~ /version/ {print $3}' build.gradle | sed 's/"//g')
popd

# LOCAL_DEV env variable need to be set in local development env
if [[ -v LOCAL_DEV ]]; then
  MVN=mvn

  # checkout latest project version
  git -C $PROJECT pull || git clone $MAIN_REPOSITORY $PROJECT

  # set_project_version_in_fuzz_targets_dependency
  
  #install
  # mvn -pl $PROJECT install -DskipTests
  (cd $PROJECT && ./gradlew build $GRADLE_ARGS)
  mvn -pl fuzz-targets install

else
  # Move seed corpus and dictionary.
  # mv $SRC/{*.zip,*.dict} $OUT

  export JAVA_HOME="$OUT/open-jdk-8"
  mkdir -p $JAVA_HOME
  rsync -aL --exclude=*.zip "/usr/lib/jvm/java-8-openjdk-amd64/" "$JAVA_HOME"

  (cd $PROJECT && ./gradlew build $GRADLE_ARGS)
  cp $SRC/project-parent/opencensus-java/api/build/libs/opencensus-api-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-api.jar
  cp $SRC/project-parent/opencensus-java/impl/build/libs/opencensus-impl-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-impl.jar
  cp $SRC/project-parent/opencensus-java/impl_core/build/libs/opencensus-impl-core-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-impl-core.jar
  cp $SRC/project-parent/opencensus-java/exporters/trace/util/build/libs/opencensus-exporter-trace-util-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-exporter-trace-util.jar
  cp $SRC/project-parent/opencensus-java/exporters/trace/ocagent/build/libs/opencensus-exporter-trace-ocagent-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-exporter-trace-ocagent.jar
  cp $SRC/project-parent/opencensus-java/contrib/resource_util/build/libs/opencensus-contrib-resource-util-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-contrib-resource-util.jar
  cp $SRC/project-parent/opencensus-java/exporters/trace/elasticsearch/build/libs/opencensus-exporter-trace-elasticsearch-$OPENCENSUS_JAVA_VERSION.jar $OUT/opencensus-exporter-trace-elasticsearch.jar
  
  ALL_JARS="opencensus-api.jar opencensus-impl.jar opencensus-impl-core.jar opencensus-exporter-trace-util.jar opencensus-contrib-resource-util.jar opencensus-exporter-trace-elasticsearch.jar"

  for fuzzer in $(find $SRC/project-parent/fuzz-targets -name '*Fuzzer.java' ! -name JsonConversionFuzzer.java); do
    $MVN -pl fuzz-targets install -Dmaven.repo.local=$OUT/m2
    $MVN -pl fuzz-targets dependency:build-classpath -Dmdep.outputFile=cp.txt -Dmaven.repo.local=$OUT/m2
    cp -r $SRC/project-parent/fuzz-targets/target/test-classes/ $OUT/
    RUNTIME_CLASSPATH_ABSOLUTE="$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$(cat fuzz-targets/cp.txt):$OUT/test-classes"
    # replace dirname with placeholder $this_dir that will be replaced at runtime
  RUNTIME_CLASSPATH=$(echo $RUNTIME_CLASSPATH_ABSOLUTE | sed "s|$OUT|\$this_dir|g")

    fuzzer_basename=$(basename -s .java $fuzzer)

    # Create an execution wrapper for every fuzztarget
    echo "#!/bin/bash
  # LLVMFuzzerTestOneInput comment for fuzzer detection by infrastructure.
  this_dir=\$(dirname \"\$0\")
  if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi
  JAVA_HOME=\"\$this_dir/open-jdk-8/\" \
  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=com.example.$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
--instrumentation_includes=\"com.**:org.**:io.**\" \
\$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
  done


  PACKAGE_NAME="io.opencensus.exporter.trace.elasticsearch"
  PACKAGE_DIR=$SRC/project-parent/fuzz-targets/src/test/java/$(echo $PACKAGE_NAME | sed 's/\./\//g')
  mkdir -p $PACKAGE_DIR
  mv $SRC/project-parent/fuzz-targets/src/test/java/com/example/JsonConversionFuzzer.java $PACKAGE_DIR

  $MVN -pl fuzz-targets install -Dmaven.repo.local=$OUT/m2
  $MVN -pl fuzz-targets dependency:build-classpath -Dmdep.outputFile=cp.txt -Dmaven.repo.local=$OUT/m2
  cp -r $SRC/project-parent/fuzz-targets/target/test-classes/ $OUT/
  RUNTIME_CLASSPATH_ABSOLUTE="$(cat fuzz-targets/cp.txt):$OUT/test-classes:$PACKAGE_NAME:$(echo $ALL_JARS | xargs printf -- "$OUT/%s:")."
  # replace dirname with placeholder $this_dir that will be replaced at runtime
  RUNTIME_CLASSPATH=$(echo $RUNTIME_CLASSPATH_ABSOLUTE | sed "s|$OUT|\$this_dir|g")

  echo "#!/bin/bash
  # LLVMFuzzerTestOneInput comment for fuzzer detection by infrastructure.
  this_dir=\$(dirname \"\$0\")
  if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi
  JAVA_HOME=\"\$this_dir/open-jdk-8/\" \
  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$PACKAGE_NAME.JsonConversionFuzzer \
--jvm_args=\"\$mem_settings\" \
--instrumentation_includes=\"com.**:org.**:io.**\" \
\$@" > $OUT/JsonConversionFuzzer
  chmod u+x $OUT/JsonConversionFuzzer

  rm -rf $PACKAGE_DIR

fi