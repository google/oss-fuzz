---
layout: default
parent: ClusterFuzzLite
title: Build Integration
has_children: true
nav_order: 2
permalink: /clusterfuzzlite/build-integration/
---
# Build integration
{: .no_toc}

- TOC
{:toc}
---

## Prerequisites
ClusterFuzzLite supports statically linked [libFuzzer targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) on Linux.

Before you can start setting up your new project for fuzzing, you must do the following:
- [Integrate]({{ site.baseurl }}/advanced-topics/ideal-integration/) one or more [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target)
  with the project you want to fuzz. For examples, see TODO.
- [Install Docker](https://docs.docker.com/engine/installation)
  (Googlers can visit [go/installdocker](https://goto.google.com/installdocker)).
  [Why Docker?]({{ site.baseurl }}/faq/#why-do-you-use-docker)

  If you want to run `docker` without `sudo`, you can
  [create a docker group](https://docs.docker.com/engine/installation/linux/ubuntulinux/#/create-a-docker-group).

  **Note:** Docker images can consume significant disk space. Run
  [docker-cleanup](https://gist.github.com/mikea/d23a839cba68778d94e0302e8a2c200f)
  periodically to garbage-collect unused images.

- Clone the OSS-Fuzz repo: `git clone https://github.com/google/oss-fuzz.git`

## Generating an empty build integration
Build integrations consist of two files, a `Dockerfile` that can install
dependencies for your project, and a `build.sh` file that actually builds your
project. These must live in the `.clusterfuzzlite` directory in the root of your
project's source code checkout.
You can generate empty versions of these files with the following command:

```bash
$ cd /path/to/oss-fuzz
$ export PATH_TO_PROJECT=<path_to_your_project>
$ python infra/helper.py generate $PATH_TO_PROJECT --external
```

Once the configuration files are generated, you should modify them to fit your
project.

## Dockerfile {#dockerfile}

This integration file defines the Docker image for your project.
Your [build.sh](#buildsh) script will be executed in inside the container you
define.
For most projects, the image is simple:
```docker
FROM gcr.io/oss-fuzz-base/base-builder          # base image with clang toolchain
RUN apt-get update && apt-get install -y ...    # install required packages to build your project
COPY . $SRC/<project_name>                      # checkout all sources needed to build your project
WORKDIR $SRC/<project_name>                     # current directory for the build script
COPY ./clusterfuzzlite/build.sh fuzzer.cc $SRC/ # copy build script into src dir
```
TODO: Provide examples.

## build.sh {#buildsh}

This file defines how to build binaries for [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) in your project.
The script is executed within the image built from your [Dockerfile](#Dockerfile).
If you are familiar with `build.sh` files from OSS-Fuzz, they work exactly the
same in ClusterFuzzLite.

In general, this script should do the following:

- Build the project using your build system with the ClusterFuzzLite's compiler.
- Provide ClusterFuzzLite's compiler flags (defined as [environment variables](#Requirements)) to the build system.
- Build your [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target)
  and link your project's build with `$LIB_FUZZING_ENGINE` (libFuzzer).

Resulting binaries should be placed in `$OUT`.

Here's an example from Expat
([source](https://github.com/google/oss-fuzz/blob/master/projects/expat/build.sh)):

```bash
#!/bin/bash -eu

./buildconf.sh
# configure scripts usually use correct environment variables.
./configure

make clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    $SRC/parse_fuzzer.cc -o $OUT/parse_fuzzer \
    $LIB_FUZZING_ENGINE .libs/libexpat.a

cp $SRC/*.dict $SRC/*.options $OUT/
```

If your project is written in Go, check out the [Integrating a Go project]({{ site.baseurl }}//getting-started/new-project-guide/go-lang/) page.

**Note:**
1. Make sure that the binary names for your [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) contain only
alphanumeric characters, underscore(_) or dash(-). Otherwise, they won't run.
1. Don't remove source code files. They are needed for code coverage.


### Temporarily disabling code instrumentation during builds

In some cases, it's not necessary to instrument every 3rd party library or tool that supports the build target. Use the following snippet to build tools or libraries without instrumentation:

```
CFLAGS_SAVE="$CFLAGS"
CXXFLAGS_SAVE="$CXXFLAGS"
unset CFLAGS
unset CXXFLAGS
export AFL_NOOPT=1

#
# build commands here that should not result in instrumented code.
#

export CFLAGS="${CFLAGS_SAVE}"
export CXXFLAGS="${CXXFLAGS_SAVE}"
unset AFL_NOOPT
```
TODO: Figure out if we should include this AFL code.

### build.sh script environment

When your build.sh script is executed, the following locations are available within the image:

| Location| Env Variable | Description |
|---------| ------------ | ----------  |
| `/out/` | `$OUT`         | Directory to store build artifacts (fuzz targets, dictionaries, options files, seed corpus archives). |
| `/src/` | `$SRC`         | Directory to checkout source files. |
| `/work/`| `$WORK`        | Directory to store intermediate files. |

Although the files layout is fixed within a container, environment variables are
provided so you can write retargetable scripts.

In case your fuzz target uses the [FuzzedDataProvider] class, make sure it is
included via `#include <fuzzer/FuzzedDataProvider.h>` directive.

[FuzzedDataProvider]: https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider

### build.sh requirements {#Requirements}

Only binaries without an extension are accepted as targets. Extensions are reserved for other artifacts, like .dict.

You *must* use the special compiler flags needed to build your project and fuzz targets.
These flags are provided in the following environment variables:

| Env Variable           | Description
| -------------          | --------
| `$CC`, `$CXX`, `$CCC`  | The C and C++ compiler binaries.
| `$CFLAGS`, `$CXXFLAGS` | C and C++ compiler flags.
| `$LIB_FUZZING_ENGINE`  | C++ compiler argument to link fuzz target against the prebuilt engine library (e.g. libFuzzer).

You *must* use `$CXX` as a linker, even if your project is written in pure C.

Most well-crafted build scripts will automatically use these variables. If not,
pass them manually to the build tool.

See the [Provided Environment Variables](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/README.md#provided-environment-variables) section in
`base-builder` image documentation for more details.

## Fuzzer execution environment

For more on the environment that
your [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) run in, and the assumptions you can make, see the [fuzzer environment]({{ site.baseurl }}/further-reading/fuzzer-environment/) page.

## Testing locally

You can build your docker image and fuzz targets locally, so you can test them
before running ClusterFuzzLite.
1. Run the same helper script you used to create your directory structure, this time using it to build your docker image and [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target):

    ```bash
    $ cd /path/to/oss-fuzz
    $ python infra/helper.py build_image $PATH_TO_PROJECT --external
    $ python infra/helper.py build_fuzzers $PATH_TO_PROJECT --sanitizer <address/undefined/coverage> --external
    ```

    The built binaries appear in the `/path/to/oss-fuzz/build/out/$PROJECT_NAME`
    directory on your machine (and `$OUT` in the container). Note that
    `$PROJECT_NAME` is the name of the directory of your project (e.g. if
    `$PATH_TO_PROJECT` is `/path/to/systemd`, `$PROJECT_NAME` is systemd.

    **Note:** You *must* run your fuzz target binaries inside the base-runner docker
    container to make sure that they work properly.

2. Find failures to fix by running the `check_build` command:

    ```bash
    $ python infra/helper.py check_build $PATH_TO_PROJECT --external
    ```

3. If you want to test changes against a particular fuzz target, run the following command:

    ```bash
    $ python infra/helper.py run_fuzzer --external --corpus-dir=<path-to-temp-corpus-dir> $PATH_TO_PROJECT <fuzz_target>
    ```

4. We recommend taking a look at your code coverage as a test to ensure that
your fuzz targets get to the code you expect. This would use the corpus
generated from the previous `run_fuzzer` step in your local corpus directory.

    ```bash
    $ python infra/helper.py build_fuzzers --sanitizer coverage $PATH_TO_PROJECT
    $ python infra/helper.py coverage $PATH_TO_PROJECT --fuzz-target=<fuzz_target> --corpus-dir=<path-to-temp-corpus-dir> --external
    ```

You may need to run `python infra/helper.py pull_images` to use the latest
coverage tools. Please refer to
[code coverage]({{ site.baseurl }}/advanced-topics/code-coverage/) for detailed
information on code coverage generation.

**Note:** Currently, ClusterFuzzLite only supports AddressSanitizer (address)
and UndefinedBehaviorSanitizer (undefined) configurations.
<b>Make sure to test each
of the supported build configurations with the above commands (build_fuzzers -> run_fuzzer -> coverage).</b>

If everything works locally, it should also work on ClusterFuzzLite. If you
check in your files and experience failures, review your [dependencies]({{site.baseurl }}/further-reading/fuzzer-environment/#dependencies).

## Debugging Problems

If you run into problems, the [Debugging page]({{ site.baseurl }}/advanced-topics/debugging/) lists ways to debug your build scripts and
[fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target).

## Efficient fuzzing

To improve your fuzz target ability to find bugs faster, you should consider the
following ways:

### Seed Corpus

OSS-Fuzz uses evolutionary fuzzing algorithms. Supplying seed corpus consisting
of good sample inputs is one of the best ways to improve [fuzz target]({{ site.baseurl }}/reference/glossary/#fuzz-target)'s coverage.

To provide a corpus for `my_fuzzer`, put `my_fuzzer_seed_corpus.zip` file next
to the [fuzz target]({{ site.baseurl }}/reference/glossary/#fuzz-target)'s binary in `$OUT` during the build. Individual files in this
archive will be used as starting inputs for mutations. The name of each file in the corpus is the sha1 checksum (which you can get using the `sha1sum` or `shasum` command) of its contents. You can store the corpus
next to source files, generate during build or fetch it using curl or any other
tool of your choice.
(example: [boringssl](https://github.com/google/oss-fuzz/blob/master/projects/boringssl/build.sh#L41)).

Seed corpus files will be used for cross-mutations and portions of them might appear
in bug reports or be used for further security research.

### Dictionaries

Dictionaries hugely improve fuzzing efficiency for inputs with lots of similar
sequences of bytes. [libFuzzer documentation](http://libfuzzer.info#dictionaries)

Put your dict file in `$OUT`. If the dict filename is the same as your target
binary name (i.e. `%fuzz_target%.dict`), it will be automatically used. If the
name is different (e.g. because it is shared by several targets), specify this
in .options file:

```
[libfuzzer]
dict = dictionary_name.dict
```

It is common for several [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target)
to reuse the same dictionary if they are fuzzing very similar inputs.
(example: [expat](https://github.com/google/oss-fuzz/blob/master/projects/expat/parse_fuzzer.options)).

### Input Size

By default, the fuzzing engine will generate input of any arbitrary length.
This might be useful to try corner cases that could lead to a
security vulnerability. However, if large inputs are not necessary to
increase the coverage of your target API, it is important to add a limit
here to significantly improve performance.

```cpp
if (size < kMinInputLength || size > kMaxInputLength)
  return 0;
```

TODO(metzman): We probably want a TOC for lang-specific guides (which we still need to add).
