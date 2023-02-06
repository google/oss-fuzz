#!/bin/bash -eu
# Copyright 2021 Google Inc.
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

PROJECT=itext7
PROJECT_GROUP_ID=com.itextpdf
PROJECT_ARTIFACT_ID=kernel
MAIN_REPOSITORY=https://github.com/itext/itext7

function set_project_version_in_fuzz_targets_dependency {
  PROJECT_VERSION=$(cd $PROJECT && $MVN org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.version -q -DforceStdout)
  # set dependency project version in fuzz-targets
  (cd fuzz-targets && $MVN versions:use-dep-version -Dincludes=$PROJECT_GROUP_ID:$PROJECT_ARTIFACT_ID -DdepVersion=$PROJECT_VERSION -DforceVersion=true)
}

cd project-parent

# LOCAL_DEV env variable need to be set in local development env
if [[ -v LOCAL_DEV ]]; then
  MVN=mvn

  # checkout latest project version
  git -C $PROJECT pull || git clone $MAIN_REPOSITORY $PROJECT

  set_project_version_in_fuzz_targets_dependency

  #install
  mvn -pl $PROJECT install -DskipTests
  mvn -pl $PROJECT/kernel install -DskipTests #only build kernel subproject (root is useless)
  mvn -pl fuzz-targets install

else
  # Move seed corpus and dictionary.
  mv $SRC/{*.zip,*.dict} $OUT

  set_project_version_in_fuzz_targets_dependency

  #install
  $MVN -pl $PROJECT install -DskipTests -Dmaven.repo.local=$OUT/m2
  $MVN -pl $PROJECT/kernel install -DskipTests -Dmaven.repo.local=$OUT/m2
  $MVN -pl fuzz-targets install -Dmaven.repo.local=$OUT/m2

  # build classpath
  $MVN -pl fuzz-targets dependency:build-classpath -Dmdep.outputFile=cp.txt -Dmaven.repo.local=$OUT/m2
  cp -r $SRC/project-parent/fuzz-targets/target/test-classes/ $OUT/test-classes
  # RUNTIME_CLASSPATH="$(cat fuzz-targets/cp.txt):$OUT/test-classes"
  RUNTIME_CLASSPATH_ABSOLUTE="$(cat fuzz-targets/cp.txt):$OUT/test-classes"
  RUNTIME_CLASSPATH_RELATIVE=$(echo $RUNTIME_CLASSPATH_ABSOLUTE | sed "s|$OUT|.|g")

  for fuzzer in $(find $SRC/project-parent -name '*Fuzzer.java'); do
    fuzzer_basename=$(basename -s .java $fuzzer)

    # Create an execution wrapper for every fuzztarget
    echo "#!/bin/bash
  # LLVMFuzzerTestOneInput comment for fuzzer detection by infrastructure.
  if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
    mem_settings='-Xmx1900m -Xss900k'
  else
    mem_settings='-Xmx2048m -Xss1024k'
  fi
  java -cp $RUNTIME_CLASSPATH_RELATIVE \
  \$mem_settings \
  com.code_intelligence.jazzer.Jazzer \
  --target_class=com.example.$fuzzer_basename \
  \$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
  done

fi