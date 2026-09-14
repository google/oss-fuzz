# OSS-Fuzz Project Structure

A project in OSS-Fuzz is defined by a directory in the `projects/` folder. This directory contains the necessary configuration and build scripts to integrate the project into the OSS-Fuzz infrastructure.

The core files required for an OSS-Fuzz project are:

## 1. `project.yaml`

This file contains metadata about the project. It is used by OSS-Fuzz to manage the project, contact maintainers, and define the fuzzing configuration.

Key fields include:
- `homepage`: The project's official website.
- `language`: The primary programming language of the project (e.g., `c++`, `go`, `rust`, `python`, `java`).
- `primary_contact`: The email address of the main person responsible for the project's integration.
- `auto_ccs`: A list of additional email addresses to be notified of issues.
- `fuzzing_engines`: The fuzzing engines to use (e.g., `libfuzzer`, `afl`, `honggfuzz`).
- `sanitizers`: The sanitizers to use (e.g., `address`, `undefined`, `memory`).
- `main_repo`: The URL of the project's source code repository.
- `base_os_version`: set to ubuntu-24-04 if base builder image used is ubuntu-24-04

## 2. `Dockerfile`

The `Dockerfile` defines the build environment for the project. It must inherit from an OSS-Fuzz base image, typically `gcr.io/oss-fuzz-base/base-builder`.

Its responsibilities include:
- Installing any necessary build dependencies (via `apt-get`).
- Checking out the project's source code (e.g., via `git clone`).
- Copying the `build.sh` script and any other necessary files into the container.
- Setting the working directory to the project's source code.

Example snippet:
```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 https://github.com/example/project.git
WORKDIR project
COPY build.sh $SRC/
```

## 3. `build.sh`

The `build.sh` script is responsible for compiling the project and its fuzz targets. It is executed inside the Docker container defined by the `Dockerfile`.

It should use environment variables provided by OSS-Fuzz:
- `$CC`, `$CXX`, `$CFLAGS`, `$CXXFLAGS`: Compilers and flags for instrumentation.
- `$OUT`: The directory where the resulting fuzzer binaries and other artifacts (like seed corpora or dictionary files) should be placed.
- `$SRC`: points to /src in the container
- `$LIB_FUZZING_ENGINE`: The library to link against for the chosen fuzzing engine.

The script typically performs the following steps:
1. Build the project's libraries using the provided compilers and flags.
2. Compile the fuzz targets and link them against the project's libraries and `$LIB_FUZZING_ENGINE`.
3. Copy the fuzzer binaries to `$OUT`.
4. (Optional) Create and copy seed corpora (as `.zip` files) and dictionaries (as `.dict` files) to `$OUT`.

Example snippet:
```bash
# Build the project
./autogen.sh
./configure
make -j$(nproc)

# Build a fuzzer
$CXX $CXXFLAGS -Iinclude \
    /path/to/fuzzer.cc -o $OUT/my_fuzzer \
    $LIB_FUZZING_ENGINE /path/to/library.a
```
