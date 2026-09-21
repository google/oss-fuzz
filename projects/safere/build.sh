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

# 1. Bundle a trimmed OpenJDK 21 for runner execution
export RUNTIME_JDK="$OUT/openjdk-21"
mkdir -p "$RUNTIME_JDK"
rsync -aL --exclude="*.zip" "/usr/lib/jvm/java-21-openjdk-amd64/" "$RUNTIME_JDK"
rm -rf "$RUNTIME_JDK/jmods" "$RUNTIME_JDK/lib/src.zip" "$RUNTIME_JDK/man"

# 2. Build SafeRE core and compile fuzz targets
mvn --batch-mode clean package test-compile -DskipTests -pl safere,safere-fuzz -am

cp safere/target/safere-*.jar "$OUT/safere.jar"
jar -cf "$OUT/safere-fuzz.jar" -C safere-fuzz/target/test-classes .

# 3. Copy runtime test dependencies (excluding jazzer which is supplied by the runtime)
mvn -pl safere-fuzz dependency:copy-dependencies -DoutputDirectory="$OUT" -DincludeScope=test -DexcludeGroupIds=com.code-intelligence

PROJECT_JARS="safere.jar safere-fuzz.jar"
for dep in "$OUT"/*.jar; do
  dep_name=$(basename "$dep")
  if [[ "$dep_name" != "safere.jar" && "$dep_name" != "safere-fuzz.jar" && "$dep_name" != jazzer* ]]; then
    PROJECT_JARS="$PROJECT_JARS $dep_name"
  fi
done

RUNTIME_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "\$this_dir/%s:"):.:\$this_dir

# 4. Generate runner scripts, dictionaries, and seed corpora
FUZZ_TARGET_DIR="$SRC/safere/safere-fuzz/src/test/java/org/safere/fuzz"
RESOURCES_DIR="$SRC/safere/safere-fuzz/src/test/resources/org/safere/fuzz"
REGEXP_DICT="$SRC/google-fuzzing/dictionaries/regexp.dict"

for fuzzer_file in "$FUZZ_TARGET_DIR"/*Fuzzer.java; do
  fuzzer_name=$(basename -s .java "$fuzzer_file")
  target_class="org.safere.fuzz.$fuzzer_name"

  cat <<EOF > "$OUT/$fuzzer_name"
#!/bin/bash
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
if [[ "\$@" =~ (^| )-runs=[0-9]+(\$| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
JAVA_HOME="\$this_dir/openjdk-21" \
LD_LIBRARY_PATH="\$this_dir/openjdk-21/lib/server":\$this_dir \
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \
--cp=$RUNTIME_CLASSPATH \
--target_class=$target_class \
--disabled_hooks=com.code_intelligence.jazzer.sanitizers.RegexInjection \
--jvm_args="\$mem_settings:-Djdk.attach.allowAttachSelf=true:--enable-native-access=ALL-UNNAMED" \
"\$@"
EOF
  chmod +x "$OUT/$fuzzer_name"

  # Dictionary
  cp "$REGEXP_DICT" "$OUT/$fuzzer_name.dict"

  # Seed corpus if available
  corpus_dir="$RESOURCES_DIR/${fuzzer_name}Inputs"
  if [ -d "$corpus_dir" ]; then
    seeds=$(find "$corpus_dir" -type f)
    if [ -n "$seeds" ]; then
      zip -q -j "$OUT/${fuzzer_name}_seed_corpus.zip" $seeds
    fi
  fi
done

