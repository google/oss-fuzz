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

# -DskipTests alone still runs the integration tests of systests/webapp-tests.
MVN_FLAGS="-DskipTests -DskipITs -Dmaven.javadoc.skip=true"
ALL_JARS=""

# Install the build servers' jazzer-api into the maven repository.
pushd "/tmp"
	${MVN} install:install-file -Dfile=${JAZZER_API_PATH} \
		-DgroupId="com.code-intelligence" \
		-DartifactId="jazzer-api" \
		-Dversion="0.12.0" \
		-Dpackaging=jar
popd

pushd "${SRC}/${LIBRARY_NAME}"
	${MVN} install ${MVN_FLAGS}
	CURRENT_VERSION=$(${MVN} org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate -Dexpression=project.version -q -DforceStdout)
popd

pushd "${SRC}/${LIBRARY_NAME}-fuzzer"
	${MVN} package -DfuzzedLibaryVersion="${CURRENT_VERSION}" ${MVN_FLAGS}
	install -v target/${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar ${OUT}/${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar
	ALL_JARS="${ALL_JARS} ${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar"

	# The dependencies stay separate jars (see the comment in the pom).
	mkdir -p ${OUT}/lib
	for jar in target/lib/*.jar; do
		install -v ${jar} ${OUT}/lib/
		ALL_JARS="${ALL_JARS} lib/$(basename ${jar})"
	done
popd



# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

# Only instrument the libraries under test, not the harness or the rest of the dependencies.
INSTRUMENTATION_INCLUDES="org.apache.axis2.**:org.apache.axiom.**:org.apache.commons.fileupload2.**:com.ctc.wstx.**:com.google.gson.**:com.squareup.moshi.**:org.codehaus.jettison.**:org.apache.ws.commons.schema.**:org.apache.james.mime4j.**"

# Fuzzer class -> seed/dictionary directory and max input length (name, dir, max_len).
declare -A SUPPORT=(
	[PipelineFuzzer]="pipeline 65536"
	[DispatchFuzzer]="dispatch 4096"
)

MVN_FUZZERS_PREFIX="src/main/java"

for fuzzer in $(find ${SRC}/${LIBRARY_NAME}-fuzzer -name '*Fuzzer.java'); do
	# Find our fuzzer inside the maven structure
	stripped_path=$(echo ${fuzzer} | sed \
		-e 's|^.*src/main/java/\(.*\).java$|\1|' \
		-e 's|^.*src/test/java/\(.*\).java$|\1|' \
	);
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
--instrumentation_includes=\"${INSTRUMENTATION_INCLUDES}\" \
--jvm_args=\"-Xmx2048m\" \
\$@" > $OUT/${fuzzer_basename}
	chmod u+x $OUT/${fuzzer_basename}

	# Seed corpus, dictionary and input length of the fuzzers that have them.
	if [ -n "${SUPPORT[${fuzzer_basename}]:-}" ]; then
		read -r support_dir max_len <<< "${SUPPORT[${fuzzer_basename}]}"
		zip -j -q $OUT/${fuzzer_basename}_seed_corpus.zip ${SRC}/${LIBRARY_NAME}-fuzzer/seeds/${support_dir}/*
		cp ${SRC}/${LIBRARY_NAME}-fuzzer/dict/${support_dir}.dict $OUT/${fuzzer_basename}.dict
		printf '[libfuzzer]\nmax_len = %s\n' ${max_len} > $OUT/${fuzzer_basename}.options
	fi
done
