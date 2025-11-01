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

PROJECT=jetty
PROJECT_GROUP_ID=org.eclipse.jetty
PROJECT_ARTIFACT_ID=jetty-project
MAIN_REPOSITORY=https://github.com/eclipse/jetty.project

MAVEN_ARGS="-Dmaven.test.skip=true -Djavac.src.version=11 -Djavac.target.version=11 -Denforcer.skip=true -DskipTests"

mv $SRC/{*.zip,*.dict} $OUT

function set_project_version_in_fuzz_targets_dependency {
  PROJECT_VERSION=$(cd $PROJECT && $MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.version -q -DforceStdout)
  FUZZ_TARGET_DEPENDENCIES=":jetty-http :jetty-server :jetty-util :jetty-io :jetty-runner :jetty-client .http2:http2-common .http2:http2-server"
  
  for dependency in $FUZZ_TARGET_DEPENDENCIES; do
    # set dependency project version in fuzz-targets
    (cd fuzz-targets && $MVN versions:use-dep-version -Dincludes=$PROJECT_GROUP_ID$dependency -DdepVersion=$PROJECT_VERSION -DforceVersion=true)
  done
}

cd project-parent

# LOCAL_DEV env variable need to be set in local development env
if [[ -v LOCAL_DEV ]]; then

  # checkout latest project version
  git -C $PROJECT pull || git clone $MAIN_REPOSITORY $PROJECT

  set_project_version_in_fuzz_targets_dependency

  #install
  (cd $PROJECT && $MVN install $MAVEN_ARGS) 
  $MVN -pl fuzz-targets install

else
  # Move seed corpus and dictionary.
  # mv $SRC/{*.zip,*.dict} $OUT
  
  set_project_version_in_fuzz_targets_dependency

  #install
  (cd $PROJECT && $MVN install $MAVEN_ARGS -Dmaven.repo.local=$OUT/m2)
  $MVN -pl fuzz-targets install -Dmaven.repo.local=$OUT/m2

  # build classpath
  $MVN -pl fuzz-targets dependency:build-classpath -Dmdep.outputFile=cp.txt -Dmaven.repo.local=$OUT/m2
  cp -r $SRC/project-parent/fuzz-targets/target/test-classes $OUT/
  RUNTIME_CLASSPATH_ABSOLUTE="$(cat fuzz-targets/cp.txt):$OUT/test-classes"
  # replace dirname with placeholder $this_dir that will be replaced at runtime
  RUNTIME_CLASSPATH=$(echo $RUNTIME_CLASSPATH_ABSOLUTE | sed "s|$OUT|\$this_dir|g")

  for fuzzer in $(find $SRC/project-parent/fuzz-targets -name '*Fuzzer.java' ! -name WebAppDefaultServletFuzzer.java); do
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
  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=com.example.$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
  done

  # disable NamingContextLookup sanitizer for WebAppDefaultServletFuzzer.java
  echo "#!/bin/bash
  # LLVMFuzzerTestOneInput comment for fuzzer detection by infrastructure.
  if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
    mem_settings='-Xmx1900m:-Xss900k'
  else
    mem_settings='-Xmx2048m:-Xss1024k'
  fi
  LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=com.example.WebAppDefaultServletFuzzer \
--disabled_hooks=com.code_intelligence.jazzer.sanitizers.NamingContextLookup \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/WebAppDefaultServletFuzzer
  chmod u+x $OUT/WebAppDefaultServletFuzzer

  # add keystore to location required by SslConnectionFuzzer
  mkdir -p /out/src/test/resources
  cp $SRC/project-parent/jetty/jetty-io/src/test/resources/keystore.p12 /out/src/test/resources/

fi