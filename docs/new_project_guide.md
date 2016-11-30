# Setting up New Project

## Prerequisites
- [Install Docker](https://docs.docker.com/engine/installation). ([Why Docker?](faq.md#why-do-you-use-docker))
- [Integrate](ideal_integration.md) one or more [Fuzz Targets](http://libfuzzer.info/#fuzz-target)
  with the project you want to fuzz.

## Overview

To add a new OSS project to OSS-Fuzz, you need a project subdirectory 
inside the [`projects/`](../projects) directory in [OSS-Fuzz repository](https://github.com/google/oss-fuzz). 
Example: [boringssl](https://github.com/google/boringssl) project is located in 
[`projects/boringssl`](../projects/boringssl).

The project directory needs to contain the following three configuration files:

* `projects/<project_name>/Dockerfile` - defines the container environment with information 
on dependencies needed to build the project and its fuzz targets.
* `projects/<project_name>/build.sh` - build script that executes inside the container and 
generates project build.
* `projects/<project_name>/project.yaml` - provides metadata about the project.

To *automatically* create a new directory for your project and 
generate templated versions of these configuration files, 
run the following set of commands:

```bash
$ cd /path/to/oss-fuzz
$ export PROJECT_NAME=<project_name>
$ python infra/helper.py generate $PROJECT_NAME
```

It is preferred to keep and maintain fuzz targets in your own source code repository. If this is not possible due to various reasons, you can store them inside the OSS-Fuzz's project directory created above.

## Dockerfile

This file defines the Docker image definition. This is where the build.sh script will be executed in. 
It is very simple for most projects:
```docker
FROM ossfuzz/base-libfuzzer               # base image with clang toolchain
MAINTAINER YOUR_EMAIL                     # maintainer for this file
RUN apt-get install -y ...                # install required packages to build your project
RUN git clone <git_url> <checkout_dir>    # checkout all sources needed to build your project
WORKDIR <checkout_dir>                    # current directory for build script
COPY build.sh fuzzer.cc $SRC/             # copy build script and other fuzzer files in src dir
```
Expat example: [expat/Dockerfile](../projects/expat/Dockerfile)

### Fuzzer execution environment

[This page](fuzzer_environment.md) gives information about the environment that
your fuzz targets will run on ClusterFuzz, and the assumptions that you can make.

## build.sh

This file describes how to build fuzz targets for your project. 
The script will be executed within the image built from `Dockerfile`.

In general, this script will need to:

1. Build the project using your build system *with* correct compiler and its flags provided as 
  *environment variables* (see below). 
2. Build the fuzz targets, linking your project's build and libFuzzer. Resulting fuzz targets 
   should be placed in `$OUT`.

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
    -lfuzzer .libs/libexpat.a

cp $SRC/*.dict $SRC/*.options $OUT/
```

### build.sh Script Environment 

When build.sh script is executed, the following locations are available within the image:

| Path                   | Description
| ------                 | -----
| `/out/` (`$OUT`)       | Directory to store build artifacts (fuzz targets, dictionaries, options files, seed corpus archives).
| `/src/` (`$SRC`)       | Directory to checkout source files.
| `/work/`(`$WORK`)      | Directory for storing intermediate files |
| `/usr/lib/libfuzzer.a` | Location of prebuilt libFuzzer library that needs to be linked into all fuzz targets (`-lfuzzer`).

You *must* use the special compiler flags needed to build your project and fuzz targets.
These flags are provided in the following environment variables:

| Env Variable           | Description
| -------------          | --------
| `$CC`, `$CXX`, `$CCC`  | The C and C++ compiler binaries.
| `$CFLAGS`, `$CXXFLAGS` | C and C++ compiler flags.

Most well-crafted build scripts will automatically use these variables. If not,
pass them manually to the build tool.

See [Provided Environment Variables](../infra/base-images/base-libfuzzer/README.md#provided-environment-variables) section in 
`base-libfuzzer` image documentation for more details.


## Testing locally

Use the helper script build docker image and fuzz targets.

```bash
$ cd /path/to/oss-fuzz
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers $PROJECT_NAME
```

This should place the built fuzz targets into `/path/to/oss-fuzz/build/out/$PROJECT_NAME`
directory on your machine (and `$OUT` in the container). You should then try to run these fuzz targets 
inside the container to make sure that they work properly:

```bash
$ python infra/helper.py run_fuzzer $PROJECT_NAME <fuzz_target>
```

If everything works locally, then it should also work on our automated builders
and ClusterFuzz.

It's recommended to look at code coverage as a sanity check to make sure that 
fuzz target gets to the code you expect.

```bash
$ python infra/helper.py coverage $PROJECT_NAME <fuzz_target>
```


## Debugging Problems

[Debugging](debugging.md) document lists ways to debug your build scripts or fuzz targets
in case you run into problems.


### Custom libFuzzer options for ClusterFuzz

By default, ClusterFuzz will run your fuzzer without any options. You can specify
custom options by creating a `my_fuzzer.options` file next to a `my_fuzzer` executable in `$OUT`:

```
[libfuzzer]
max_len = 1024
```

[List of available options](http://llvm.org/docs/LibFuzzer.html#options). Use of `max_len` is highly recommended.

For out of tree fuzz targets, you will likely add options file using docker's
`COPY` directive and will copy it into output in build script. 
(example: [woff2](https://github.com/google/oss-fuzz/blob/master/projects/woff2/convert_woff2ttf_fuzzer.options)).


### Seed Corpus

OSS-Fuzz uses evolutionary fuzzing algorithms. Supplying seed corpus consisting
of good sample inputs is one of the best ways to improve fuzz target's coverage.

To provide a corpus for `my_fuzzer`, put `my_fuzzer_seed_corpus.zip` file next
to the fuzz target binary in `$OUT` during the build. Individual files in this 
archive will be used as starting inputs for mutations. You can store the corpus 
next to source files, generate during build or fetch it using curl or any other 
tool of your choice. 
(example: [boringssl](https://github.com/google/oss-fuzz/blob/master/projects/boringssl/build.sh#L42)).

Seed corpus files will be used for cross-mutations and portions of them might appear
in bug reports or be used for further security research. It is important that corpus
has an appropriate and consistent license.


### Dictionaries

Dictionaries hugely improve fuzz target's effectiveness for inputs with lots of similar
sequences of bytes. [libFuzzer documentation](http://llvm.org/docs/LibFuzzer.html#dictionaries)

Put your dict file in `$OUT` and specify in .options file:

```
[libfuzzer]
dict = dictionary_name.dict
```

It is common for several fuzz targets to reuse the same dictionary if they are fuzzing very similar inputs.
(example: [expat](https://github.com/google/oss-fuzz/blob/master/projects/expat/parse_fuzzer.options)).

## project.yaml

This file stores the metadata about your project. This includes things like project's homepage, 
list of sanitizers used, list of ccs on newly filed bugs, etc. 
(example: [expat](https://github.com/google/oss-fuzz/blob/master/projects/expat/project.yaml)).

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
ClusterFuzz after a short while!<BR><BR> 
Check your project's build status [here](https://oss-fuzz-build-logs.storage.googleapis.com/status.html).
