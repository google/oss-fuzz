---
name: fuzzing-jvm-expert
description:
  Use this skill to fuzz open source JVM projects (Java, Kotlin, Scala, etc.)
  using Jazzer.
---

# Fuzzing JVM expert

This skill provides the agent with the knowledge and tools to write, build, and
validate fuzz targets for JVM-based projects (Java, Kotlin, Scala, Groovy)
integrated into OSS-Fuzz. JVM fuzzing uses
[Jazzer](https://github.com/CodeIntelligenceTesting/jazzer), which wraps
libFuzzer and instruments JVM bytecode for coverage guidance.

## Fundamental Concepts

### OSS-Fuzz base image

JVM projects must use the JVM base builder image:

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder-jvm
```

Set `language: jvm` in `project.yaml`.

### Harness structure — raw bytes

The simplest Jazzer harness receives raw bytes via `fuzzerTestOneInput`:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class MyTargetFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            MyLibrary.parse(data);
        } catch (ExpectedExceptionType e) {
            // Ignore expected exceptions; they are not bugs.
        }
    }
}
```

### Harness structure — typed input via FuzzedDataProvider

`FuzzedDataProvider` splits the raw byte stream into typed values, which is
essential for targets that require structured input:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class MyTargetFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String header    = data.consumeString(64);
        int    version   = data.consumeInt();
        byte[] payload   = data.consumeRemainingAsBytes();

        try {
            MyLibrary.process(header, version, payload);
        } catch (IllegalArgumentException | IOException e) {
            // Expected — not a finding.
        }
    }
}
```

Useful `FuzzedDataProvider` methods:

| Method | Description |
|---|---|
| `consumeBytes(n)` | `byte[]` of length n |
| `consumeRemainingAsBytes()` | all remaining bytes |
| `consumeString(maxLen)` | arbitrary String |
| `consumeAsciiString(maxLen)` | ASCII-only String |
| `consumeInt()` / `consumeInt(min, max)` | int |
| `consumeLong()` | long |
| `consumeBoolean()` | boolean |
| `consumeDouble()` | double |
| `pickValue(collection)` | random element |

### One-time setup with `fuzzerInitialize`

If initialisation is expensive (loading config, creating DB connections, etc.),
put it in an optional static method that Jazzer calls once before fuzzing:

```java
public class MyTargetFuzzer {
    private static MyClient client;

    public static void fuzzerInitialize() {
        client = new MyClient(/* static config */);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        client.process(data.consumeRemainingAsBytes());
    }
}
```

### Building in OSS-Fuzz

The `build.sh` pattern for Maven projects:

```bash
# Build the project JARs.
$MVN package -DskipTests -Dmaven.javadoc.skip=true

# Collect JARs needed at runtime.
ALL_JARS="mylib-1.0.jar"
BUILD_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH
RUNTIME_CLASSPATH=$(echo $ALL_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -maxdepth 1 -name '*Fuzzer.java'); do
    fuzzer_basename=$(basename -s .java "$fuzzer")
    javac -cp $BUILD_CLASSPATH "$fuzzer"
    cp $SRC/$fuzzer_basename.class $OUT/

    # Wrapper script that launches jazzer_driver with the right arguments.
    echo "#!/bin/bash
this_dir=\$(dirname \"\$0\")
if [[ \"\$@\" =~ (^| )-runs=[0-9]+($| ) ]]; then
  mem_settings='-Xmx1900m:-Xss900k'
else
  mem_settings='-Xmx2048m:-Xss1024k'
fi
LD_LIBRARY_PATH=\"$JVM_LD_LIBRARY_PATH\":\$this_dir \\
\$this_dir/jazzer_driver --agent_path=\$this_dir/jazzer_agent_deploy.jar \\
--instrumentation_includes=com.example.** \\
--cp=$RUNTIME_CLASSPATH \\
--target_class=$fuzzer_basename \\
--jvm_args=\"\$mem_settings\" \\
\$@" > $OUT/$fuzzer_basename
    chmod u+x $OUT/$fuzzer_basename
done
```

For Gradle projects replace `$MVN package` with the appropriate Gradle command
and adjust JAR paths accordingly.

### Seed corpus and dictionaries

- Zip seed files to `$OUT/<fuzzer_name>_seed_corpus.zip`.
- Place dictionaries at `$OUT/<fuzzer_name>.dict`.

## Characteristics of good JVM fuzzing harnesses

1. **Targets attack surface**: parsers, deserializers (JSON, XML, Protobuf,
   custom binary formats), network protocol handlers, template engines, and
   any API that accepts untrusted bytes or strings.
2. **Catches expected exceptions**: wrap calls in `try/catch` for all
   documented exception types. Only unexpected exceptions and crashes are
   findings.
3. **Uses `FuzzedDataProvider`** for structured input rather than passing raw
   bytes to methods that expect well-formed data.
4. **Initialises heavy state in `fuzzerInitialize`**: client connections,
   parsers with complex configuration, and loaded schemas should be set up once.
5. **Avoids non-determinism**: no `Math.random()`, no `System.currentTimeMillis()`
   in the fuzzing path, no thread spawning.
6. **Sets `--instrumentation_includes`** to the package prefix of the target
   library in the wrapper script — without this Jazzer cannot guide fuzzing.
7. **Configures JVM memory appropriately**: use the `mem_settings` pattern
   shown above to avoid OOM kills during runs vs. crash reproduction.
8. **Avoids false positives**: `OutOfMemoryError`, `StackOverflowError`, and
   `NullPointerException` on invalid input are usually expected — decide which
   are genuine bugs for this project.

## What JVM fuzzing finds

- **Unexpected exceptions**: `NullPointerException`, `ArrayIndexOutOfBoundsException`,
  `ClassCastException`, `NumberFormatException` on paths that should not throw.
- **Assertion errors and contract violations**: internal consistency checks
  that fail on adversarial input.
- **Hang / infinite loops**: detected by OSS-Fuzz's timeout.
- **Security bugs**: deserialization gadgets, path traversal via crafted
  filenames, SSRF via crafted URLs — depends on the library.
- **Logic bugs**: incorrect output for valid-ish input.

Jazzer can also detect:
- SQL injection (via JDBC hooks)
- Path traversal (via file API hooks)
- Command injection (via `Runtime.exec` hooks)

## Operational guidelines

- Always validate with:
  ```
  python3 infra/helper.py build_fuzzers <project>
  python3 infra/helper.py check_build <project>
  python3 infra/helper.py run_fuzzer <project> <fuzzer_name> -- -max_total_time=30
  ```
- An instant crash usually means a missing JAR on the classpath or an
  uncaught expected exception — check `check_build` output carefully.
- Build the project outside the fuzzing harness first (`mvn package` or
  `gradle build`) to ensure the project itself compiles cleanly.
- When iterating locally clone the upstream repo and switch the Dockerfile from
  `RUN git clone` to `COPY` to avoid network round-trips.
- Document why each entry point was chosen and what class of bugs it may find.
