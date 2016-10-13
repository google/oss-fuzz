# base-libfuzzer
> Abstract base image for libfuzzer builders.

Supported commands:

* `docker run -ti <image_name> [compile]` - compiles everything. Expects /src/ paths
  to be mounted.
* `docker run -ti <image_name> checkout_and_compile` - checks projects sources out 
  if its location is defined and compiles.
* `docker run -ti <image_name> run <fuzzer_name> <fuzzer_options...>` - build fuzzers and start
  specified one with given options.
* `docker run -ti <image_name> /bin/bash` - drop into shell. Run `compile` script
  to start build. 

# Image Files Layout

| Location | Description |
| -------- | ----------  |
| `/out/` | build artifacts should be copied here  |
| `/work/` | used to store intermediate files |
| `/work/libfuzzer/*.o` | libfuzzer object files |

# Provided Environment Variables

You *must* use special compiler flags to build your library and fuzzers.
These flags are provided in following environment variables:

| Env Variable    | Description
| -------------   | --------
| `$CC`           | The C compiler binary.
| `$CXX`, `$CCC`  | The C++ compiler binary.
| `$CFLAGS`       | C compiler flags.
| `$CXXFLAGS`     | C++ compiler flags.
| `$FUZZER_LDFLAGS`      | Linker flags for fuzzer binaries.

Many well-crafted build scripts will automatically use these variables. If not,
passing them manually to a build tool might be required.

# Child Image Interface

## Required Files

Following files have to be added by child images:

| File Location | Description |
| ------------- | ----------- |
| `/src/build.sh` | build script to build the library and its fuzzers |

## Optional Environment Variables

Child image can define following environment variables:

| Variable | Description |
| -------- | ----------- |
| `GIT_URL` (optional) | git url for sources |
| `SVN_URL` (optional) | svn url for sources |
| `GIT_CHECKOUT_DIR` (optional) | directory (under `/src/`) to checkout into |
| `SVN_CHECKOUT_DIR` (optional) | directory (under `/src/`) to checkout into |

