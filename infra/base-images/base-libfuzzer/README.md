# base-libfuzzer
> Abstract base image for libfuzzer builders.

`docker run -ti <image_name> <command> <arguments>`

# Supported Commands

| Command | Description |
|---------|-------------|
| `compile` (default) | build all fuzzers
| `reproduce <fuzzer_name> <fuzzer_options>` | build all fuzzers and run specified one with `/testcase` content.
| `run <fuzzer_name> <fuzzer_options...>` | build all fuzzers and run specified one with given options.
| `test` | build all fuzzers and run each one for a little while to verify it is working correctly.
| `/bin/bash` | drop into shell, execute `compile` script to start build.

# Image Files Layout


| Location | Description |
| -------- | ----------  |
| `/out/` (`$OUT`)       | build artifacts should be copied here  |
| `/src/` (`$SRC`)       | place to checkout source files |
| `/work/`(`$WORK`)      | used to store intermediate files |
| `/usr/lib/libfuzzer.a` | libfuzzer static library |

While files layout is fixed within a container, `$SRC`, `$OUT`, `$WORK` are
provided to be able to write retargetable scripts.


## Compiler Flags

You *must* use special compiler flags to build your target and fuzzers.
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

## Sources

Child image has to checkout all sources it needs to compile fuzzers into
`$SRC` directory. When the image is executed, a directory could be mounted
on top of these with local checkouts using
`docker run -v $HOME/my_target:/src/my_target ...`.

## Other Required Files

Following files have to be added by child images:

| File Location   | Description |
| -------------   | ----------- |
| `$SRC/build.sh` | build script to build the target and its fuzzers |
