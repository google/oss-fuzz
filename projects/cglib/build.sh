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

#
# cglib uses different variables for the java version.
#
MVN_FLAGS="-Dmaven.compiler.source=15 -Dmaven.compiler.target=15 -DskipTests  -Djava.version.source=15 -Djava.version.target=15 -Djavac.target=15"
ALL_JARS=""

# install the build servers' jazzer-api into the maven repository
pushd "/tmp"
	${MVN} install:install-file -Dfile=${JAZZER_API_PATH} \
		-DgroupId="com.code-intelligence" \
		-DartifactId="jazzer-api" \
		-Dversion="0.12.0" \
		-Dpackaging=jar
popd

pushd "${SRC}/cglib"
	${MVN} package ${MVN_FLAGS}
	${MVN} install ${MVN_FLAGS}
	CURRENT_VERSION=$(${MVN} org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
  -Dexpression=project.version -q -DforceStdout)
popd

pushd ${SRC}
	${MVN} package -DcglibVersion="${CURRENT_VERSION}" ${MVN_FLAGS}
	install -v target/cglib-fuzzer-${CURRENT_VERSION}.jar ${OUT}/cglib-fuzzer-${CURRENT_VERSION}.jar
	ALL_JARS="${ALL_JARS} cglib-fuzzer-${CURRENT_VERSION}.jar"
popd



# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

MVN_FUZZERS_PREFIX="src/main/java"

for fuzzer in $(find ${SRC} -name '*Fuzzer.java'); do
  stripped_path=$(echo ${fuzzer} | sed 's|^.*src/main/java/\(.*\).java$|\1|');
  # the .java was stripped by sed
  if (echo ${stripped_path} | grep ".java$"); then
	continue;
  fi

  fuzzer_basename=$(basename -s .java $fuzzer)
  fuzzer_classname=$(echo ${stripped_path} | sed 's|/|.|g');

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.

export JAVA_HOME=$JAVA_15_HOME
export JVM_LD_LIBRARY_PATH=$JAVA_HOME/lib/server
export PATH=$JAVA_HOME/bin:$PATH

this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=${RUNTIME_CLASSPATH} \
--target_class=${fuzzer_classname} \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/${fuzzer_basename}
  chmod u+x $OUT/${fuzzer_basename}
done
