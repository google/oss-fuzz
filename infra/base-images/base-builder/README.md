# base-builder
> Abstract base image for project builders.

Every project image supports multiple commands that can be invoked through docker after the image is built:

<pre>
docker run --rm -ti gcr.io/oss-fuzz/<b><i>$project</i></b> <i>&lt;command&gt;</i> <i>&lt;arguments...&gt;</i>
</pre>

# Supported Commands

| Command | Description |
|---------|-------------|
| `compile` (default) | build all fuzz targets
| `/bin/bash` | drop into shell, execute `compile` script to start build.

# Build Configuration

A single build image can build same set of fuzzers in many configurations.
The configuration is picked through one or more environment variables.

| Env Variable     | Description
| -------------    | --------
| `$SANITIZER ("address")` | Specifies predefined sanitizer configuration to use. `address` or `memory` or `undefined`.
| `$SANITIZER_FLAGS` | Specify compiler sanitizer flags directly. Overrides `$SANITIZER`.
| `$COVERAGE_FLAGS` | Specify compiler flags to use for fuzzer feedback coverage.
| `$BUILD_UID` | User id to use while building fuzzers.

## Examples

- *building sqlite3 fuzzer with UBSan (`SANITIZER=undefined`):*


<pre>
docker run --rm -ti -e <i>SANITIZER</i>=<i>undefined</i> gcr.io/oss-fuzz/sqlite3
</pre>


# Image Files Layout

| Location|Env| Description |
|---------| -------- | ----------  |
| `/out/` | `$OUT`         | Directory to store build artifacts (fuzz targets, dictionaries, options files, seed corpus archives). |
| `/src/` | `$SRC`         | Directory to checkout source files |
| `/work/`| `$WORK`        | Directory for storing intermediate files |
| `/usr/lib/libFuzzingEngine.a` | `$LIB_FUZZING_ENGINE` | Location of prebuilt fuzzing engine library (e.g. libFuzzer) that needs to be linked with all fuzz targets.

While files layout is fixed within a container, the environment variables are
provided to be able to write retargetable scripts.


## Compiler Flags

You *must* use special compiler flags to build your project and fuzz targets.
These flags are provided in following environment variables:

| Env Variable    | Description
| -------------   | --------
| `$CC`           | The C compiler binary.
| `$CXX`, `$CCC`  | The C++ compiler binary.
| `$CFLAGS`       | C compiler flags.
| `$CXXFLAGS`     | C++ compiler flags.

Most well-crafted build scripts will automatically use these variables. If not,
pass them manually to the build tool.


# Child Image Interface

## Sources

Child image has to checkout all sources that it needs to compile fuzz targets into
`$SRC` directory. When the image is executed, a directory could be mounted on top
of these with local checkouts using
`docker run -v $HOME/my_project:/src/my_project ...`.

## Other Required Files

Following files have to be added by child images:

| File Location   | Description |
| -------------   | ----------- |
| `$SRC/build.sh` | build script to build the project and its fuzz targets |
