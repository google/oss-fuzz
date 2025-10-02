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

PROJECT=tika
MAIN_REPOSITORY=https://github.com/apache/tika/

MAVEN_ARGS="-Djavac.src.version=17 -Djavac.target.version=17 -DskipTests -Dcheckstyle.skip -Dossindex.skip -am -pl :tika-app"

function set_project_version_in_fuzz_targets_dependency {
  PROJECT_VERSION=$(cd $PROJECT && $MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.version -q -DforceStdout)
  # set dependency project version in fuzz-targets
  (cd fuzz-targets && $MVN versions:use-dep-version -Dexcludes=com.code-intelligence:jazzer -DdepVersion=$PROJECT_VERSION -DforceVersion=true)
}

cd $SRC/project-parent

set_project_version_in_fuzz_targets_dependency

#install
(cd $PROJECT && $MVN install $MAVEN_ARGS -Dmaven.repo.local=$OUT/m2)
$MVN -pl fuzz-targets install -Dmaven.repo.local=$OUT/m2

# build classpath
cp  $SRC/project-parent/fuzz-targets/target/fuzz-targets-0.0.1-SNAPSHOT.jar $OUT/fuzz-targets.jar
RUNTIME_CLASSPATH_ABSOLUTE="$OUT/fuzz-targets.jar"
# replace $OUT with placeholder $this_dir that will be dissolved at runtime
RUNTIME_CLASSPATH=$(echo $RUNTIME_CLASSPATH_ABSOLUTE | sed "s|$OUT|\$this_dir|g")

cp ${SRC}/seeds/*_seed_corpus.zip ${OUT}/

for fuzzer in $(find $SRC/project-parent -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)

  # Create an execution wrapper for every fuzztarget
  # This bumps memory to > 2gb to get around new byte[Integer.MAX_VALUE] single
  # allocation issues that plague audio, video, image and other parsers.
  # if we're able to get an oom > 2gb, we should really fix that.
  echo "#!/bin/bash
  # LLVMFuzzerTestOneInput comment for fuzzer detection by infrastructure.
  this_dir=\$(dirname \"\$0\")
  mem_settings='-Xmx3000m:-Xss1024k'
  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
  \$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
  --cp=$RUNTIME_CLASSPATH \
  --target_class=com.example.$fuzzer_basename \
  -rss_limit_mb=3600mb \
  --jvm_args=\"\$mem_settings\" \
  --instrumentation_includes=\"com.**:org.**\" \
  \$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
done