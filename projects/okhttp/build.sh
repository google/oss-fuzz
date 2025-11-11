#!/bin/bash -eu
# Build OkHttp and Jazzer fuzz targets; copy artifacts to $OUT

export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
export PATH="$JAVA_HOME/bin:$PATH"

OKHTTP_SRC_DIR="/src/okhttp"
FUZZ_SRC_DIR="$OKHTTP_SRC_DIR/fuzz"
FUZZ_BUILD_DIR="$FUZZ_SRC_DIR/build"
JAZZER_API="/usr/local/share/jazzer/api"

# If the source is not already present under /src/okhttp, you can clone here.
# Example (uncomment and adjust):
# git clone --depth 1 https://github.com/square/okhttp.git "$OKHTTP_SRC_DIR"

# Build OkHttp with Gradle wrapper, preferring the JVM target for MPP
if [ -f "$OKHTTP_SRC_DIR/gradlew" ]; then
  pushd "$OKHTTP_SRC_DIR" >/dev/null
  # Try the MPP JVM jar task first; fall back to assemble
  if ./gradlew --no-daemon :okhttp:jvmJar -x test -x javadoc; then
    echo "Built :okhttp:jvmJar"
  else
    echo ":okhttp:jvmJar not available, trying :okhttp:assemble"
    ./gradlew --no-daemon :okhttp:assemble -x test -x javadoc
  fi
  popd >/dev/null
fi

# Prepare jazzer target(s)
mkdir -p "$OUT" "$FUZZ_BUILD_DIR"

# Locate OkHttp jars produced by the build (MPP jvmJar or standard jar)
OKHTTP_JARS=$(find "$OKHTTP_SRC_DIR/okhttp/build/libs" -maxdepth 1 -type f -name "*.jar" 2>/dev/null || true)

# Compile sample fuzzer (uses Jazzer JUnit FuzzTest)
CLASSPATH="$JAZZER_API/*"
if [ -n "$OKHTTP_JARS" ]; then
  CLASSPATH="$OKHTTP_SRC_DIR/okhttp/build/libs/*:$CLASSPATH"
fi

javac -encoding UTF-8 -cp "$CLASSPATH" "$FUZZ_SRC_DIR/UrlFuzzer.java" -d "$FUZZ_BUILD_DIR"

# Package runtime: copy needed jars and fuzzer classes into $OUT
cp -f $OKHTTP_SRC_DIR/okhttp/build/libs/*.jar "$OUT" 2>/dev/null || true
cp -f /usr/local/share/jazzer/*.jar "$OUT" 2>/dev/null || true
mkdir -p "$OUT/fuzzer-classes"
cp -r "$FUZZ_BUILD_DIR"/* "$OUT/fuzzer-classes" 2>/dev/null || true

# Create execution wrapper for OSS-Fuzz
cat >"$OUT/UrlFuzzer" << 'EOF'
#!/bin/bash
set -euo pipefail
THIS_DIR=$(cd -- "$(dirname "$0")" && pwd)
JAZZER_JAR=$(ls "$THIS_DIR"/jazzer*.jar | head -n1)
CP="$THIS_DIR/*:$THIS_DIR/fuzzer-classes:$THIS_DIR"
exec java -cp "$CP" com.code_intelligence.jazzer.Jazzer \
  --cp="$CP" \
  --target_class=UrlFuzzer \
  --instrumentation_includes='okhttp3.**'
EOF
chmod +x "$OUT/UrlFuzzer"
