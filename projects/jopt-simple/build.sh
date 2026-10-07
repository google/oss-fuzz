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

MVN_FLAGS="-DskipTests"
ALL_JARS=""
LIBRARY_NAME="jopt-simple"

# Install the build servers' jazzer-api into the maven repository.
pushd "/tmp"
	${MVN} install:install-file -Dfile=${JAZZER_API_PATH} \
		-DgroupId="com.code-intelligence" \
		-DartifactId="jazzer-api" \
		-Dversion="0.12.0" \
		-Dpackaging=jar
popd

pushd "${SRC}/${LIBRARY_NAME}"
    # Compile and package the project
	${MVN} clean package ${MVN_FLAGS}
	CURRENT_VERSION=$(${MVN} org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
  		-Dexpression=project.version -q -DforceStdout)
    
    # Log contents of target directory for debug
    echo "Contents of target directory:"
    ls target/
    
    # Directly hard code the target jar name based on existing listing
    TARGET_JAR="target/jopt-simple-fuzzer-${CURRENT_VERSION}.jar"
    if [[ ! -f "$TARGET_JAR" ]]; then
        echo "ERROR: Expected target jar not found!"
        exit 1
    fi

    # Log the found jar
    echo "Target jar found: $TARGET_JAR"

    # Install the jar
	${MVN} ${MVN_FLAGS} install:install-file -Dfile=${TARGET_JAR} \
		-DgroupId="net.sf.jopt-simple" \
		-DartifactId="jopt-simple" \
		-Dversion="${CURRENT_VERSION}" \
		-Dpackaging=jar

    # Execute second Maven command in correct directory
    ${MVN} package -DfuzzedLibaryVersion="${CURRENT_VERSION}" ${MVN_FLAGS}
    install -v ${TARGET_JAR} ${OUT}/${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar
    ALL_JARS="${ALL_JARS} ${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar"

    # Ensure `OptionParserFuzzer` is included in classpath
    FUZZER_CLASSPATH="$OUT/jopt-simple-fuzzer-${CURRENT_VERSION}.jar:$JAZZER_API_PATH"

    for fuzzer in $(find ${SRC}/src/main/java/ossfuzz -name '*.java'); do
        # Compile fuzzer into jar if not present
        javac -cp $FUZZER_CLASSPATH -d $OUT $fuzzer || echo "Compilation of $fuzzer failed"
    done

popd

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

MVN_FUZZERS_PREFIX="src/main/java"

for fuzzer in $(find ${SRC} -name '*Fuzzer.java'); do
	# Find our fuzzer inside the maven structure
	stripped_path=$(echo ${fuzzer} | sed \
		-e 's|^.*src/main/java/\(.*\).java$|\1|' \
		-e 's|^.*src/test/java/\(.*\).java$|\1|');
	# The .java suffix was stripped by sed.
	if (echo ${stripped_path} | grep ".java$"); then
		continue;
	fi
	
	fuzzer_basename=$(basename -s .java $fuzzer)
	fuzzer_classname=$(echo ${stripped_path} | sed 's|/|.|g');
	
	# Create an execution wrapper that executes Jazzer with the correct arguments.
	
	echo "#!/bin/sh
# LLVMFuzzerTestOneInput Magic String required for infra/base-images/base-runner/test_all.py. DO NOT REMOVE


this_dir=\$(dirname \"\$0\")
LD_LIBRARY_PATH=\"\$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=${RUNTIME_CLASSPATH} \
--target_class=${fuzzer_classname} \
--jvm_args=\"\$@\"" > $OUT/$(basename -s .java $fuzzer).sh
	chmod +x $OUT/$(basename -s .java $fuzzer).sh
done