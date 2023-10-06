---
layout: default
title: Integrating a Java/JVM project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 4
permalink: /getting-started/new-project-guide/jvm-lang/
---

# Integrating a Java/JVM project
{: .no_toc}

- TOC
{:toc}
---

The process of integrating a project written in Java or any other language
running on the Java Virtual Machine (JVM) with OSS-Fuzz is very similar to the
general
[Setting up a new project]({{ site.baseurl }}/getting-started/new-project-guide/)
process. The key specifics of integrating a JVM project are outlined below.

## Jazzer

Java fuzzing in OSS-Fuzz depends on
[Jazzer](https://github.com/CodeIntelligenceTesting/jazzer), which is
pre-installed on the OSS-Fuzz base docker images. As Jazzer operates directly
on the bytecode level, it can be applied to any project written in a JVM-based
language. More information on how Jazzer fuzz targets look like can be found in
its
[README's Usage section](https://github.com/CodeIntelligenceTesting/jazzer#usage).

## Project files

### Example project

We recommend viewing
[json-sanitizer](https://github.com/google/oss-fuzz/tree/master/projects/json-sanitizer)
as an example of a simple Java-only fuzzing project. Additional examples,
including one for a Java project with native dependencies, are part of the
[java-example](https://github.com/google/oss-fuzz/tree/master/projects/java-example)
project.

### project.yaml

The `language` attribute must be specified as follows:

```yaml
language: jvm
```

The only supported fuzzing engine is libFuzzer (`libfuzzer`). So far the only
supported sanitizers are AddressSanitizer (`address`) and
UndefinedBehaviorSanitizer (`undefined`). For pure Java projects, specify
just `address`:

```yaml
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
```

### Dockerfile

The Dockerfile should start by `FROM gcr.io/oss-fuzz-base/base-builder-jvm`

The OSS-Fuzz base Docker images already come with OpenJDK 15 pre-installed. If
you need Maven to build your project, you can install it by adding the following
line to your Dockerfile:

```docker
RUN apt-get update && apt-get install -y maven
```

Apart from this, you should usually not need to do more than to clone the
project, set a `WORKDIR`, and copy any necessary files, or install any
project-specific dependencies here as you normally would.

### Fuzzers

In the simplest case, every fuzzer consists of a single Java file with a
filename matching `*Fuzzer.java` and no `package` directive. An example fuzz
target could thus be a file `ExampleFuzzer.java` with contents:

```java
public class ExampleFuzzer {
    public static void fuzzerTestOneInput(byte[] input) {
        ...
        // Call a function of the project under test with arguments derived from
        // input and throw an exception if something unwanted happens.
        ...
    }
}
```

### build.sh

For JVM projects, `build.sh` does need some more significant modifications
over C/C++ projects. Below is an annotated example build script for a
Java-only project with single-file fuzz targets as described above:

```sh
# Step 1: Build the project

# Build the project .jar as usual, e.g. using Maven.
mvn package
# In this example, the project is built with Maven, which typically includes the
# project version into the name of the packaged .jar file. The version can be
# obtained as follows:
CURRENT_VERSION=$(mvn org.apache.maven.plugins:maven-help-plugin:3.2.0:evaluate \
-Dexpression=project.version -q -DforceStdout)
# Copy the project .jar into $OUT under a fixed name.
cp "target/sample-project-$CURRENT_VERSION.jar" $OUT/sample-project.jar

# Specify the projects .jar file(s), separated by spaces if there are multiple.
PROJECT_JARS="sample-project.jar"

# Step 2: Build the fuzzers (should not require any changes)

# The classpath at build-time includes the project jars in $OUT as well as the
# Jazzer API.
BUILD_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "$OUT/%s:"):$JAZZER_API_PATH

# All .jar and .class files lie in the same directory as the fuzzer at runtime.
RUNTIME_CLASSPATH=$(echo $PROJECT_JARS | xargs printf -- "\$this_dir/%s:"):\$this_dir

for fuzzer in $(find $SRC -name '*Fuzzer.java'); do
  fuzzer_basename=$(basename -s .java $fuzzer)
  javac -cp $BUILD_CLASSPATH $fuzzer
  cp $SRC/$fuzzer_basename.class $OUT/

  # Create an execution wrapper that executes Jazzer with the correct arguments.
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
--target_class=$fuzzer_basename \
--jvm_args=\"\$mem_settings:-Djava.awt.headless=true\" \
\$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done
```

The [java-example](https://github.com/google/oss-fuzz/blob/master/projects/java-example/build.sh)
project contains an example of a `build.sh` for Java projects with native
libraries.

## FuzzedDataProvider

Jazzer provides a `FuzzedDataProvider` that can simplify the task of creating a
fuzz target by translating the raw input bytes received from the fuzzer into
useful primitive Java types. Its functionality is similar to
`FuzzedDataProviders` available in other languages, such as
[Python](https://github.com/google/atheris#fuzzeddataprovider) and
[C++](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md).

On OSS-Fuzz, the required library is available in the base docker images under
the path `$JAZZER_API_PATH`, which is added to the classpath by the example
build script shown above. Locally, the library can be obtained from
[Maven Central](https://search.maven.org/search?q=g:com.code-intelligence%20a:jazzer-api).

A fuzz target using the `FuzzedDataProvider` would look as follows:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class ExampleFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int number = data.consumeInt();
        String string = data.consumeRemainingAsString();
        // ...
    }
}
```

For a list of convenience methods offered by `FuzzedDataProvider`, consult its
[javadocs](https://codeintelligencetesting.github.io/jazzer-docs/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html).
