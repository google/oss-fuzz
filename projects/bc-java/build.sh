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

# Set encoding to UTF-8 for Java compilation
export JAVA_TOOL_OPTIONS="-Dfile.encoding=UTF-8"

# Disable ErrorProne by removing it from annotation processor path
# ErrorProne requires Java 21+ but the base image has Java 17
cat > /tmp/disable-errorprone.gradle << 'EOF'
allprojects {
    afterEvaluate {
        tasks.withType(JavaCompile).configureEach {
            options.errorprone.enabled = false
            options.compilerArgs.removeAll { it.startsWith('-Xplugin:ErrorProne') }
        }
        // Remove errorprone from annotation processor configuration
        configurations.matching { it.name.toLowerCase().contains('errorprone') }.all {
            dependencies.clear()
        }
    }
}
EOF

# Build only Java 8/11/15/17 compatible versions, skip the Java 23 and Java 25 tasks
$GRADLE jar -x compileJava23Java -x java23Classes -x compileJava25Java -x java25Classes --init-script /tmp/disable-errorprone.gradle
find . -name "bcpkix-*.jar" -path "*/build/libs/*" ! -name "*sources*" ! -name "*javadoc*" -exec cp {} $OUT/bcpkix.jar \;
find . -name "bcutil-*.jar" -path "*/build/libs/*" ! -name "*sources*" ! -name "*javadoc*" -exec cp {} $OUT/bcutil.jar \;
find . -name "bcprov-*.jar" -path "*/build/libs/*" ! -name "*sources*" ! -name "*javadoc*" -exec cp {} $OUT/bcprov.jar \;
find . -name "bcpg-*.jar" -path "*/build/libs/*" ! -name "*sources*" ! -name "*javadoc*" -exec cp {} $OUT/bcpg.jar \;

# bcprov carries the core classes, so there is no separate core jar
ALL_JARS="bcprov.jar bcutil.jar bcpkix.jar bcpg.jar"

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -encoding UTF-8 -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
  echo "#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+(\$| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--keep_going=20 \
--cp=$RUNTIME_CLASSPATH \
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer_basename
  chmod u+x $OUT/$fuzzer_basename
done

# Seed corpora, from the test resources of bc-java and the parts of bc-test-data the Dockerfile
# fetches. Every file under the paths given goes in, named by its SHA-1 as libFuzzer names corpus
# files, so that files sharing a name in different directories do not collide and duplicates collapse.
seed_corpus() {
  name=$1; shift
  dir=$(mktemp -d)
  find "$@" -type f -size -256k | while read -r f; do
    cp "$f" "$dir/$(sha1sum "$f" | cut -c1-40)"
  done
  (cd "$dir" && zip -q $OUT/${name}_seed_corpus.zip *)
  rm -rf "$dir"
}

TESTDATA=$SRC/bc-test-data
PKITS=$SRC/bc-java/pkix/src/test/resources/PKITS
seed_corpus X509Fuzzer $PKITS/certs $PKITS/crls
seed_corpus ASN1Fuzzer $PKITS/certs $PKITS/crls $TESTDATA/asn1 $TESTDATA/rfc4134
seed_corpus CMSFuzzer $TESTDATA/rfc4134 $TESTDATA/pkix/cms
seed_corpus PEMParserFuzzer $SRC/bc-java/pkix/src/test/resources/org/bouncycastle/openssl
seed_corpus PGPFuzzer $TESTDATA/pgpdata $SRC/bc-java/pg/src/test/resources/org/bouncycastle/openpgp/test
seed_corpus PKCS12Fuzzer $TESTDATA/pkix/pkcs12 \
  $(find $TESTDATA/asn1 $SRC/bc-java/prov/src/test/resources $SRC/bc-java/pkix/src/test/resources \( -name '*.p12' -o -name '*.pfx' \))
seed_corpus TSPFuzzer $TESTDATA/tsp
seed_corpus CMPFuzzer $TESTDATA/cmp
seed_corpus OpenPGPCertificateFuzzer $TESTDATA/openpgp/openpgp-pqc $TESTDATA/pgpdata

# KeyInfoFuzzer's and OCSPFuzzer's seeds are generated: keys of each algorithm, and signed OCSP
# responses and requests, encoded as the library built here writes them
javac -encoding UTF-8 -cp $BUILD_CLASSPATH -d /tmp/seedgen $SRC/KeySeedGenerator.java $SRC/OCSPSeedGenerator.java
java -cp $BUILD_CLASSPATH:/tmp/seedgen KeySeedGenerator /tmp/keyseeds
seed_corpus KeyInfoFuzzer /tmp/keyseeds
java -cp $BUILD_CLASSPATH:/tmp/seedgen OCSPSeedGenerator /tmp/ocspseeds
seed_corpus OCSPFuzzer /tmp/ocspseeds

cp $SRC/PEMParserFuzzer.dict $OUT/
