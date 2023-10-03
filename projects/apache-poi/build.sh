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

MVN_FLAGS="--no-transfer-progress -DskipTests"
ALL_JARS=""
LIBRARY_NAME="poi"
GRADLE_FLAGS="-x javadoc -x test -Dfile.encoding=UTF-8 -Porg.gradle.java.installations.fromEnv=JAVA_HOME_8,JAVA_HOME_11 --console=plain"

echo Copy libraries for java.awt in place
ls /usr/lib/x86_64-linux-gnu/
cp /usr/lib/x86_64-linux-gnu/libXext.so.6* \
  /usr/lib/x86_64-linux-gnu/libX11.so.6* \
  /usr/lib/x86_64-linux-gnu/libXrender.so.1* \
  /usr/lib/x86_64-linux-gnu/libXtst.so.6* \
  /usr/lib/x86_64-linux-gnu/libXi.so.6* \
  /usr/lib/x86_64-linux-gnu/libxcb.so.1* \
  /usr/lib/x86_64-linux-gnu/libXau.so.6* \
  /usr/lib/x86_64-linux-gnu/libXdmcp.so.6* \
  ${OUT}/

echo Main Java
${JAVA_HOME}/bin/java -version

echo Java 8
${JAVA_HOME_8}/bin/java -version

echo Java 11
${JAVA_HOME_11}/bin/java -version

# Install the build servers' jazzer-api into the maven repository.
pushd "/tmp"
	${MVN} install:install-file -Dfile=${JAZZER_API_PATH} \
		-DgroupId="com.code-intelligence" \
		-DartifactId="jazzer-api" \
		-Dversion="0.12.0" \
		-Dpackaging=jar \
		 ${MVN_FLAGS}
popd

pushd "${SRC}/${LIBRARY_NAME}"
	# build and publish current binaries
	./gradlew publishToMavenLocal ${GRADLE_FLAGS}

	# determine current version-tag
	CURRENT_VERSION=$(./gradlew properties ${GRADLE_FLAGS} | sed -nr "s/^version:\ (.*)/\1/p")

	# prepare some seed-corpus archives based on the test-data of Apache POI
	# we cannot do this automatically as there is not a 1:1 match of fuzz targets and formats
	zip -r $OUT/POIFuzzer_seed_corpus.zip test-data
	zip -jr $OUT/POIHDGFFuzzer_seed_corpus.zip test-data/diagram/*.vsd
	zip -jr $OUT/POIHMEFFuzzer_seed_corpus.zip test-data/hmef/*
	zip -jr $OUT/POIHPBFFuzzer_seed_corpus.zip test-data/publisher/*
	zip -jr $OUT/POIHPSFFuzzer_seed_corpus.zip test-data/hpsf/*
	zip -jr $OUT/POIHSLFFuzzer_seed_corpus.zip test-data/slideshow/*.ppt
	zip -jr $OUT/POIHSMFFuzzer_seed_corpus.zip test-data/hsmf/*
	zip -jr $OUT/POIHSSFFuzzer_seed_corpus.zip test-data/spreadsheet/*.xls
	zip -jr $OUT/POIHWPFFuzzer_seed_corpus.zip test-data/document/*.doc test-data/document/*.DOC
	zip -jr $OUT/POIOldExcelFuzzer_seed_corpus.zip test-data/spreadsheet/*.xls test-data/spreadsheet/*.bin
	zip -jr $OUT/POIVisioFuzzer_seed_corpus.zip test-data/diagram/*
	zip -jr $OUT/POIXSLFFuzzer_seed_corpus.zip test-data/slideshow/* test-data/integration/*.pptx
	zip -jr $OUT/POIXSSFFuzzer_seed_corpus.zip test-data/spreadsheet/* test-data/integration/*.xslx
	zip -jr $OUT/POIXWPFFuzzer_seed_corpus.zip test-data/document/* test-data/integration/*.docx
	zip -jr $OUT/XLSX2CSVFuzzer_seed_corpus.zip test-data/spreadsheet/*
popd

pushd "${SRC}"
	${MVN} package -DfuzzedLibaryVersion="${CURRENT_VERSION}" ${MVN_FLAGS}
	install -v target/${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar ${OUT}/${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar
	ALL_JARS="${ALL_JARS} ${LIBRARY_NAME}-fuzzer-${CURRENT_VERSION}.jar"
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
--instrumentation_includes=org.apache.poi.**:org.apache.xmlbeans.** \
--target_class=${fuzzer_classname} \
--jvm_args=\"-Xmx1024m\" \
\$@" > $OUT/${fuzzer_basename}
	chmod u+x $OUT/${fuzzer_basename}
done