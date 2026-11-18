#!/bin/bash -eu
# Copyright 2026 Google LLC
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

# The Kotlin/JVM implementation of the Swell Protocol (android/swellprotocol) and its fuzz targets (android/fuzz).
# Gradle (wrapper 8.14.3, JDK 17 from the base image) builds the library, the fuzz jar and the seed corpora.
cd $SRC/swell-protocol/android
export GRADLE_USER_HOME=${GRADLE_USER_HOME:-$SRC/gradle-home}
./gradlew --no-daemon --console=plain -q :fuzz:fuzzJars :fuzz:seedCorpus

FUZZ_OUT=fuzz/build/fuzz-out
cp $FUZZ_OUT/*.jar $OUT/
RUNTIME_CLASSPATH=$(cd $FUZZ_OUT && ls *.jar | xargs printf -- "\$this_dir/%s:")\$this_dir

FUZZERS="WireFuzzer CodecFuzzer HandshakeFuzzer RatchetFuzzer SessionRecordFuzzer SignatureFuzzer InviteFuzzer LinkFuzzer"
for fuzzer in $FUZZERS; do
  # Seed corpus from docs/protocol-vectors (written by :fuzz:seedCorpus).
  (cd fuzz/build/seeds/$fuzzer && zip -q -r $OUT/${fuzzer}_seed_corpus.zip .)

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
--target_class=com.jijilabsdigital.swell.protocol.fuzz.$fuzzer \
'--instrumentation_includes=com.jijilabsdigital.swell.protocol.**' \
'--instrumentation_excludes=com.jijilabsdigital.swell.protocol.fuzz.**' \
--jvm_args=\"\$mem_settings\" \
\$@" > $OUT/$fuzzer
  chmod +x $OUT/$fuzzer
done
