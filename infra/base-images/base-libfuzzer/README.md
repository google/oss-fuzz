# base-libfuzzer
> Abstract base image for libfuzzer builders.

Every project image supports multiple commands that can be invoked through docker after the image is built:

<pre>
docker run --rm -ti ossfuzz/<b><i>$project</i></b> <i>&lt;command&gt;</i> <i>&lt;arguments...&gt;</i>
</pre>

# Supported Commands

| Command | Description |
|---------|-------------|
| `compile` (default) | build all fuzz targets
| `reproduce <fuzzer_name> <fuzzer_options>` | build all fuzz targets and run specified one with testcase `/testcase` and given options.
| `run <fuzzer_name> <fuzzer_options...>` | build all fuzz targets and run specified one with given options.
| `/bin/bash` | drop into shell, execute `compile` script to start build.

# Examples

- *Reproduce using latest OSS-Fuzz build:*

   <pre>
docker run --rm -ti -v <b><i>$testcase_file</i></b>:/testcase ossfuzz/<b><i>$project</i></b> reproduce <b><i>$fuzzer</i></b>
   </pre>

- *Reproduce using local source checkout:*

    <pre>
    docker run --rm -ti -v <b><i>$local_source_checkout_dir</i></b>:/src/<b><i>$project</i></b> \
                        -v <b><i>$testcase_file</i></b>:/testcase ossfuzz/<b><i>$project</i></b> reproduce <b><i>$fuzzer</i></b>
    </pre>


# Image Files Layout

| Location | Description |
| -------- | ----------  |
| `/out/` (`$OUT`)       | Directory to store build artifacts (fuzz targets, dictionaries, options files, seed corpus archives). |
| `/src/` (`$SRC`)       | Directory to checkout source files |
| `/work/`(`$WORK`)      | Directory for storing intermediate files |
| `/usr/lib/libfuzzer.a` | Location of prebuilt libFuzzer library that needs to be linked into all fuzz targets (`-lfuzzer`). |

While files layout is fixed within a container, `$SRC`, `$OUT`, `$WORK` are
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
