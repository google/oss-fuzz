# Setting up a New Project

## Prerequisites
- [Integrate](ideal_integration.md) one or more [Fuzz Targets](glossary.md#fuzz-target)
  with the project you want to fuzz.<BR>
  Examples:
[boringssl](https://github.com/google/boringssl/tree/master/fuzz),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338),
[s2n](https://github.com/awslabs/s2n/tree/master/tests/fuzz),
[openssl](https://github.com/openssl/openssl/tree/master/fuzz),
[FreeType](http://git.savannah.gnu.org/cgit/freetype/freetype2.git/tree/src/tools/ftfuzzer),
[re2](https://github.com/google/re2/tree/master/re2/fuzzing),
[harfbuzz](https://github.com/behdad/harfbuzz/tree/master/test/fuzzing),
[pcre2](http://vcs.pcre.org/pcre2/code/trunk/src/pcre2_fuzzsupport.c?view=markup),
[ffmpeg](https://github.com/FFmpeg/FFmpeg/blob/master/tools/target_dec_fuzzer.c).

- [Install Docker](installing_docker.md). ([Why Docker?](faq.md#why-do-you-use-docker))


## Overview

To add a new OSS project to OSS-Fuzz, you need a project subdirectory
inside the [`projects/`](../projects) directory in [OSS-Fuzz repository](https://github.com/google/oss-fuzz).
Example: [boringssl](https://github.com/google/boringssl) project is located in
[`projects/boringssl`](../projects/boringssl).

The project directory needs to contain the following three configuration files:

* `projects/<project_name>/project.yaml` - provides metadata about the project.
* `projects/<project_name>/Dockerfile` - defines the container environment with information
on dependencies needed to build the project and its [fuzz targets](glossary.md#fuzz-target).
* `projects/<project_name>/build.sh` - build script that executes inside the container and
generates project build.

To *automatically* create a new directory for your project and
generate templated versions of these configuration files,
run the following set of commands:

```bash
$ cd /path/to/oss-fuzz
$ export PROJECT_NAME=<project_name>
$ python infra/helper.py generate $PROJECT_NAME
```

It is preferred to keep and maintain [fuzz targets](glossary.md#fuzz-target) in your own source code repository. If this is not possible due to various reasons, you can store them inside the OSS-Fuzz's project directory created above.

## project.yaml

This file stores the metadata about your project. The following attributes are supported:

* `homepage` - Project's homepage.
* `primary_contact`, `auto_ccs` - Primary contact and CCs list. These people get access to ClusterFuzz 
which includes crash reports, fuzzer statistics, etc and are auto-cced on newly filed bugs in OSS-Fuzz
tracker.
* `sanitizers` (optional) - List of sanitizers to use. By default, you shouldn't override this and it 
will use the default list of supported sanitizers (currently -
AddressSanitizer("address"), UndefinedBehaviorSanitizer("undefined")). 
If your project does not build with a particular sanitizer configuration and you need some time fixing
it, then you can use this option to override the defaults temporarily. E.g. For disabling 
UndefinedBehaviourSanitizer build, then you can just specify all supported sanitizers, except "undefined".

Example: [boringssl](https://github.com/google/oss-fuzz/blob/master/projects/boringssl/project.yaml).

## Dockerfile

This file defines the Docker image definition. This is where the build.sh script will be executed in.
It is very simple for most projects:
```docker
FROM gcr.io/oss-fuzz-base/base-builder               # base image with clang toolchain
MAINTAINER YOUR_EMAIL                     # maintainer for this file
RUN apt-get install -y ...                # install required packages to build your project
RUN git clone <git_url> <checkout_dir>    # checkout all sources needed to build your project
WORKDIR <checkout_dir>                    # current directory for build script
COPY build.sh fuzzer.cc $SRC/             # copy build script and other fuzzer files in src dir
```
Expat example: [expat/Dockerfile](../projects/expat/Dockerfile)

In the above example, the git clone will check out the source to `$SRC/<checkout_dir>`. 

## build.sh

This file describes how to build [fuzz targets](glossary.md#fuzz-target) for your project.
The script will be executed within the image built from `Dockerfile`.

In general, this script will need to:

1. Build the project using your build system *with* correct compiler and its flags provided as
  *environment variables* (see below).
2. Build the [fuzz targets](glossary.md#fuzz-target), linking your project's build and libFuzzer.
   Resulting binaries should be placed in `$OUT`.

*Note*:

1. Please don't assume that the fuzzing engine is libFuzzer and hardcode in your build scripts.
In future, we will add support for other fuzzing engines like AFL.
So, link the fuzzing engine using `-lFuzzingEngine`, see example below.
2. Please make sure that the binary names for your [fuzz targets](glossary.md#fuzz-target) contain only
alphanumeric characters, underscore(_) or dash(-). Otherwise, they won't run on our infrastructure.

For expat, this looks like [this](https://github.com/google/oss-fuzz/blob/master/projects/expat/build.sh):

```bash
#!/bin/bash -eu

./buildconf.sh
# configure scripts usually use correct environment variables.
./configure

make clean
make -j$(nproc) all

$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    $SRC/parse_fuzzer.cc -o $OUT/parse_fuzzer \
    -lFuzzingEngine .libs/libexpat.a

cp $SRC/*.dict $SRC/*.options $OUT/
```

### build.sh Script Environment

When build.sh script is executed, the following locations are available within the image:

| Location|Env| Description |
|---------| -------- | ----------  |
| `/out/` | `$OUT`         | Directory to store build artifacts (fuzz targets, dictionaries, options files, seed corpus archives). |
| `/src/` | `$SRC`         | Directory to checkout source files |
| `/work/`| `$WORK`        | Directory for storing intermediate files |
| `/usr/lib/libFuzzingEngine.a` | `$LIB_FUZZING_ENGINE` | Location of prebuilt fuzzing engine library (e.g. libFuzzer ) that needs to be linked with all fuzz targets (`-lFuzzingEngine`).

While files layout is fixed within a container, the environment variables are
provided to be able to write retargetable scripts.

You *must* use the special compiler flags needed to build your project and fuzz targets.
These flags are provided in the following environment variables:

| Env Variable           | Description
| -------------          | --------
| `$CC`, `$CXX`, `$CCC`  | The C and C++ compiler binaries.
| `$CFLAGS`, `$CXXFLAGS` | C and C++ compiler flags.

Most well-crafted build scripts will automatically use these variables. If not,
pass them manually to the build tool.

See [Provided Environment Variables](../infra/base-images/base-builder/README.md#provided-environment-variables) section in
`base-builder` image documentation for more details.

## Fuzzer execution environment

[This page](fuzzer_environment.md) gives information about the environment that
your [fuzz targets](glossary.md#fuzz-target) will run on ClusterFuzz, and the assumptions that you can make.

## Testing locally

Use the helper script to build docker image and [fuzz targets](glossary.md#fuzz-target).

```bash
$ cd /path/to/oss-fuzz
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers -e SANITIZER=<address/memory/undefined> $PROJECT_NAME
```

This should place the built binaries into `/path/to/oss-fuzz/build/out/$PROJECT_NAME`
directory on your machine (and `$OUT` in the container).

*Note*: You *must* run these fuzz target binaries inside the base-runner docker
container to make sure that they work properly:

```bash
$ python infra/helper.py run_fuzzer $PROJECT_NAME <fuzz_target>
```

If everything works locally, then it should also work on our automated builders and ClusterFuzz.
If it fails, check out [this](fuzzer_environment.md#dependencies) entry.

It's recommended to look at code coverage as a sanity check to make sure that
[fuzz target](glossary.md#fuzz-target) gets to the code you expect.

```bash
$ python infra/helper.py coverage $PROJECT_NAME <fuzz_target>
```

*Note*: Currently, we only support AddressSanitizer (address) and UndefinedBehaviorSanitizer (undefined) 
configurations. MemorySanitizer is in development mode and not recommended for use. <b>Make sure to test each
of the supported build configurations with the above commands (build_fuzzers -> run_fuzzer -> coverage).</b>

## Debugging Problems

[Debugging](debugging.md) document lists ways to debug your build scripts or
[fuzz targets](glossary.md#fuzz-target)
in case you run into problems.


## Custom libFuzzer options for ClusterFuzz

By default, ClusterFuzz will run your fuzzer without any options. You can specify
custom options by creating a `my_fuzzer.options` file next to a `my_fuzzer` executable in `$OUT`:

```
[libfuzzer]
max_len = 1024
```

[List of available options](http://llvm.org/docs/LibFuzzer.html#options). Use of `max_len` is highly recommended.

For out of tree [fuzz targets](glossary.md#fuzz-target), you will likely add options file using docker's
`COPY` directive and will copy it into output in build script.
(example: [woff2](https://github.com/google/oss-fuzz/blob/master/projects/woff2/convert_woff2ttf_fuzzer.options)).


### Seed Corpus

OSS-Fuzz uses evolutionary fuzzing algorithms. Supplying seed corpus consisting
of good sample inputs is one of the best ways to improve [fuzz target](glossary.md#fuzz-target)'s coverage.

To provide a corpus for `my_fuzzer`, put `my_fuzzer_seed_corpus.zip` file next
to the [fuzz target](glossary.md#fuzz-target)'s binary in `$OUT` during the build. Individual files in this
archive will be used as starting inputs for mutations. You can store the corpus
next to source files, generate during build or fetch it using curl or any other
tool of your choice.
(example: [boringssl](https://github.com/google/oss-fuzz/blob/master/projects/boringssl/build.sh#L41)).

Seed corpus files will be used for cross-mutations and portions of them might appear
in bug reports or be used for further security research. It is important that corpus
has an appropriate and consistent license.


### Dictionaries

Dictionaries hugely improve fuzzing efficiency for inputs with lots of similar
sequences of bytes. [libFuzzer documentation](http://libfuzzer.info#dictionaries)

Put your dict file in `$OUT` and specify in .options file:

```
[libfuzzer]
dict = dictionary_name.dict
```

It is common for several [fuzz targets](glossary.md#fuzz-target)
to reuse the same dictionary if they are fuzzing very similar inputs.
(example: [expat](https://github.com/google/oss-fuzz/blob/master/projects/expat/parse_fuzzer.options)).

## Checking in to OSS-Fuzz repository

Fork OSS-Fuzz, commit and push to the fork, and then create a pull request with
your change! Follow the [Forking Project](https://guides.github.com/activities/forking/) guide
if you are new to contributing via GitHub.

### Copyright headers

Please include copyright headers for all files checked in to oss-fuzz:

```
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
```

If you are porting a fuzz target from Chromium, keep the original Chromium license header.

## The end

Once your change is merged, your project and fuzz targets should be automatically built and run on
ClusterFuzz after a short while (&lt; 1 day)!<BR><BR>
Check your project's build status [here](https://oss-fuzz-build-logs.storage.googleapis.com/status.html).<BR>
Check out the crashes generated and code coverage statistics on [ClusterFuzz](clusterfuzz.md) web interface [here](https://oss-fuzz.com/).
