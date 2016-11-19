# Setting up New Target

Fuzzer configurations are placed into a subdirectories inside the [`targets/` dir](../targets) 
of the [oss-fuzz repo] on GitHub. 
For example, the configuration files for the
[boringssl](https://github.com/google/boringssl) targets are located in 
[`targets/boringssl`](../targets/boringssl).

## Prerequisites
- [Install Docker](https://docs.docker.com/engine/installation). ([Why Docker?](faq.md#why-do-you-use-docker))
  - Googlers: [go/installdocker](https://goto.google.com/installdocker).
  - NOTE: if you want to run `docker` without `sudo` also follow the optional 
    [Create a docker group](https://docs.docker.com/engine/installation/linux/ubuntulinux/#/create-a-docker-group) section.
  - NOTE: Docker images can consume significant disk space. Run
    [docker-cleanup](https://gist.github.com/mikea/d23a839cba68778d94e0302e8a2c200f)
    periodically to garbage collect unused images.
- [Itegrate](ideal_integration.md) one or more [Fuzz Target](http://libfuzzer.info/#fuzz-target)
  with the project you want to fuzz.

## Overview

To add a new OSS target to OSS-Fuzz, 3 supporting files have to be added to OSS-Fuzz source code repository:

* `targets/<target_name>/Dockerfile` - defines an container environment with all the dependencies
needed to build the project and the fuzzer.
* `targets/<target_name>/build.sh` - build script that will be executed inside the container.
* `targets/<target_name>/Jenkinsfile` - will be needed to integrate fuzzers with ClusterFuzz build and distributed execution system. 
  Specify your target VCS location in it.

To create a new directory for the target and *automatically generate* these 3 files a python script can be used:

```bash
$ cd /path/to/oss-fuzz
$ export TARGET_NAME=target_name
$ python infra/helper.py generate $TARGET_NAME
```

Create a fuzzer and add it to the *target_name/* directory as well.

## Dockerfile

This is the Docker image definition that build.sh will be executed in.
It is very simple for most libraries:
```docker
FROM ossfuzz/base-libfuzzer               # base image with clang toolchain
MAINTAINER YOUR_EMAIL                     # each file should have a maintainer
RUN apt-get install -y ...                # install required packages to build a project
RUN git checkout <git_url> <checkout_dir> # checkout all sources needed to build your target
WORKDIR <checkout_dir>                    # current directory for build script
COPY build.sh fuzzer.cc $SRC/             # install build script and other source files.
```
Expat example: [expat/Dockerfile](../targets/expat/Dockerfile)

### Fuzzer execution environment

[This page](fuzzer_environment.md) gives information about the environment that
your fuzzers will run under on ClusterFuzz, and the assumptions that you can
make.

## build.sh

This is where most of the work is done to build fuzzers for your target. The script will
be executed within an image built from a `Dockerfile`.

In general, this script will need to:

1. Build the target using its build system *with* correct compiler and its flags provided as 
  *environment variables* (see below). 
2. Build the fuzzers, linking with the target and libFuzzer. Resulting fuzzers
   should be placed in `/out`.

For expat, this looks like:

```bash
#!/bin/bash -eu

./buildconf.sh
# configure scripts usually use correct environment variables.
./configure

make -j$(nproc) clean all

# build the fuzzer, linking with libFuzzer and libexpat.a
$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    $SRC/parse_fuzzer.cc -o /out/expat_parse_fuzzer \
    -lfuzzer .libs/libexpat.a
```

### build.sh Script Environment 

When build.sh script is executed, the following locations are available within the image:

| Path                   | Description
| ------                 | -----
| `$SRC/<some_dir>`      | Source code needed to build your target.
| `/usr/lib/libfuzzer.a` | Prebuilt libFuzzer library that need to be linked into all fuzzers (`-lfuzzer`).

You *must* use special compiler flags to build your target and fuzzers.
These flags are provided in following environment variables:

| Env Variable           | Description
| -------------          | --------
| `$CC`, `$CXX`, `$CCC`  | The C and C++ compiler binaries.
| `$CFLAGS`, `$CXXFLAGS` | C and C++ compiler flags.

Many well-crafted build scripts will automatically use these variables. If not,
passing them manually to a build tool might be required.

See [Provided Environment Variables](../infra/base-images/base-libfuzzer/README.md#provided-environment-variables) section in 
`base-libfuzzer` image documentation for more details.


## Testing locally

Helper script can be used to build images and fuzzers. Non-script
version using docker commands directly is documented [here](building_running_fuzzers_external.md).

```bash
$ cd /path/to/oss-fuzz
$ python infra/helper.py build_image $TARGET_NAME
$ python infra/helper.py build_fuzzers $TARGET_NAME
```

This should place the built fuzzers into `/path/to/oss-fuzz/build/out/$TARGET_NAME`
on your machine (`/out` in the container). You can then try to run these fuzzers
inside the container to make sure that they work properly:

```bash
$ python infra/helper.py run_fuzzer $TARGET_NAME name_of_a_fuzzer
```

If everything works locally, then it should also work on our automated builders
and ClusterFuzz.

It's recommended to look at coverage as a sanity check to make sure that fuzzer gets to the code you expect.

```bash
$ python infra/helper.py coverage $TARGET_NAME name_of_a_fuzzer
```


## Debugging Problems

[Debugging](debugging.md) document lists ways to debug your build scripts or fuzzers
in case you run into problems.


### Custom libFuzzer options for ClusterFuzz

By default ClusterFuzz will run your fuzzer without any options. You can specify
custom options by creating a `my_fuzzer.options` file next to a `my_fuzzer` executable in `/out`:

```
[libfuzzer]
max_len = 1024
```

[List of available options](http://llvm.org/docs/LibFuzzer.html#options)

At least `max_len` is highly recommended.

For out of tree fuzzers you will likely add options file using docker's
`COPY` directive and will copy it into output in build script. 
([Woff2 example](https://github.com/google/oss-fuzz/blob/master/targets/woff2/convert_woff2ttf_fuzzer.options).)


### Seed Corpus

oss-fuzz uses evolutionary fuzzing algorithms. Supplying seed corpus consisting
of sample inputs is one of the best ways to improve fuzzer coverage.

To provide a corpus for `my_fuzzer`, put `my_fuzzer_seed_corpus.zip` file next
to the fuzzer binary in `/out` during the build. Individual files in the zip file 
will be used as starting inputs for mutations. You can store the corpus next to 
source files, generate during build or fetch it using curl or any other tool of 
your choice. 
([Boringssl example](https://github.com/google/oss-fuzz/blob/master/targets/boringssl/build.sh#L42).)

Seed corpus files will be used for cross-mutations and portions of them might appear
in bug reports or be used for further security research. It is important that corpus
has an appropriate and consistent license.


### Dictionaries

Dictionaries hugely improve fuzzer effectiveness for inputs with lots of similar
sequences of bytes. [libFuzzer documentation](http://llvm.org/docs/LibFuzzer.html#dictionaries)

Put your dict file in `/out` and specify in .options file:

```
[libfuzzer]
dict = dictionary_name.dict
```

It is common for several fuzzers to reuse the same dictionary if they are fuzzing very similar inputs.
([Expat example](https://github.com/google/oss-fuzz/blob/master/targets/expat/parse_fuzzer.options).)

## Jenkinsfile

This file will be largely the same for most libraries, and is used by our build
infrastructure. For expat, this is:

```groovy
// load libFuzzer pipeline definition.
def libfuzzerBuild = fileLoader.fromGit('infra/libfuzzer-pipeline.groovy',
                                        'https://github.com/google/oss-fuzz.git')

libfuzzerBuild {
  git = "git://git.code.sf.net/p/expat/code_git"
}
```

Simply replace the "git" entry with the correct git url for the target.

*Note*: only git is supported right now.

## Checking in to oss-fuzz repository

Fork oss-fuzz, commit and push to the fork, and then create a pull request with
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

If porting a fuzzer from Chromium, keep the Chromium license header.

## The end

Once your change is merged, the fuzzers should be automatically built and run on
ClusterFuzz after a short while!

[oss-fuzz repo]: https://github.com/google/oss-fuzz
[dictionaries]: http://llvm.org/docs/LibFuzzer.html#dictionaries
[Install Docker]: https://docs.docker.com/engine/installation/linux/ubuntulinux/
