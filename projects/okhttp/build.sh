#!/bin/bash -eu
# Build OkHttp and Jazzer fuzz targets; copy artifacts to $OUT

export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
export PATH="$JAVA_HOME/bin:$PATH"

OKHTTP_SRC_DIR="/src/okhttp"
FUZZ_SRC_DIR="$OKHTTP_SRC_DIR/fuzz"
FUZZ_BUILD_DIR="$FUZZ_SRC_DIR/build"
JAZZER_API="/usr/local/share/jazzer/api"
DEFAULT_FUZZ_SRC="/opt/okhttp-fuzz"

# If the source is not already present under /src/okhttp, you can clone here.
# Example (uncomment and adjust):
# git clone --depth 1 https://github.com/square/okhttp.git "$OKHTTP_SRC_DIR"

# Build OkHttp with Gradle (prefer system gradle to avoid wrapper downloads)
GRADLE_CMD=""
if command -v gradle >/dev/null 2>&1; then
  GRADLE_CMD="$(command -v gradle)"
elif [ -f "$OKHTTP_SRC_DIR/gradlew" ]; then
  GRADLE_CMD="$OKHTTP_SRC_DIR/gradlew"
fi

if [ -n "$GRADLE_CMD" ]; then
  pushd "$OKHTTP_SRC_DIR" >/dev/null
  # Try the MPP JVM jar task first; fall back to assemble
  if "$GRADLE_CMD" --no-daemon :okhttp:jvmJar -x test -x javadoc; then
    echo "Built :okhttp:jvmJar"
  else
    echo ":okhttp:jvmJar not available, trying :okhttp:assemble"
    "$GRADLE_CMD" --no-daemon :okhttp:assemble -x test -x javadoc
  fi
  popd >/dev/null
else
  echo "Gradle not found; please ensure gradle is installed in the image." >&2
  exit 1
fi

# Ensure fuzz harness exists (copy from image if not present in source)
if [ ! -f "$FUZZ_SRC_DIR/UrlFuzzer.java" ] && [ -d "$DEFAULT_FUZZ_SRC" ]; then
  mkdir -p "$FUZZ_SRC_DIR"
  cp -r "$DEFAULT_FUZZ_SRC"/. "$FUZZ_SRC_DIR/"
fi

# Prepare jazzer target(s)
mkdir -p "$OUT" "$FUZZ_BUILD_DIR"
# Ensure downstream tests always have at least one artifact in /out.
touch "$OUT/.placeholder"

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
# Copy jazzer drivers expected by OSS-Fuzz runner
if [ -d /usr/local/share/jazzer/bin ]; then
  cp -f /usr/local/share/jazzer/bin/jazzer_driver "$OUT" 2>/dev/null || true
  cp -f /usr/local/share/jazzer/bin/jazzer_driver_with_sanitizer "$OUT" 2>/dev/null || true
  chmod +x "$OUT"/jazzer_driver* 2>/dev/null || true
fi
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
