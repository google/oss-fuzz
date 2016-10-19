# Setting up fuzzers for a new library

Fuzzer build configurations are placed into a top-level directory for the
library in the [oss-fuzz repo] on GitHub. For example, fuzzers for the expat
library go into <https://github.com/google/oss-fuzz/tree/master/expat>.

## Prerequisites

[Install Docker]. (Googlers: [go/installdocker](https://goto.google.com/installdocker) )

*NOTE: if you want to run `docker` without `sudo` also follow the optional [Create a docker group](https://docs.docker.com/engine/installation/linux/ubuntulinux/#/create-a-docker-group) section.*

*NOTE: Docker images can consume significant disk space. Run*
*[docker-cleanup](https://gist.github.com/mikea/d23a839cba68778d94e0302e8a2c200f)*
*periodically to garbage collect unused images.*


Building fuzzers requires building your library with a fresh
Clang compiler and special compiler flags. An easy-to-use Docker image is 
provided to simplify tool distribution.

If you'd like to get more familiar with how libFuzzer-style fuzzers work in
general, check out [this page](http://llvm.org/docs/LibFuzzer.html).

## Overview

To add a new OSS library to oss-fuzz, 3 supporting files have to be added to oss-fuzz source code repository:

* `library_name/Dockerfile` - defines an container environment with all the dependencies
needed to build the project and the fuzzer.
* `library_name/build.sh` - build script that will be executed inside the container.
* `library_name/Jenkinsfile` - will be needed to integrate fuzzers with ClusterFuzz build and distributed execution system. 
  Specify your library VCS location in it.

To create a new directory for the library and *automatically generate* these 3 files a python script can be used:

```bash
$ cd /path/to/oss-fuzz
$ export LIB_NAME=name_of_the_library
$ python scripts/helper.py generate $LIB_NAME
```

Create a fuzzer and add it to the *library_name/* directory as well.

## Dockerfile

This is the Docker image definition that build.sh will be executed in.
It is very simple for most libraries:
```docker
FROM ossfuzz/base-libfuzzer             # base image with clang toolchain
MAINTAINER YOUR_EMAIL                   # each file should have a maintainer
RUN apt-get install -y ...              # install required packages to build a project
RUN git checkout <git_url>              # checkout all sources needed to build your library
COPY build.sh fuzzer.cc /src/           # install build script and other source files.
```
Expat example: [expat/Dockerfile](../expat/Dockerfile)

## Create Fuzzer Source File

Create a new .cc file, define a `LLVMFuzzerTestOneInput` function and call
your library:

```c++
#include <stddef.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // put your fuzzing code here and use data+size as input.
  return 0;
}
```

Make sure you add the file to your Docker image:
```docker
COPY build.sh my_fuzzer.cc /src/         # install build script & fuzzer.
```

There are [lots](../libxml2/libxml2_xml_read_memory_fuzzer.cc)
[of](../expat/parse_fuzzer.cc) [examples](../zlib/zlib_uncompress_fuzzer.cc)
in this project repository.

## build.sh

This is where most of the work is done to build fuzzers for your library. The script will
be executed within an image built from a `Dockerfile`.

In general, this script will need to:

1. Build the library using its build system *with* correct compiler and its flags provided as *environment variables* (see below). 
2. Build the fuzzers, linking with the library and libFuzzer. Built fuzzers
   should be placed in `/out`.

For expat, this looks like:

```bash
#!/bin/bash -eu

cd /src/expat/expat
./buildconf.sh
# configure scripts usually use correct environment variables.
./configure

make clean all

# build the fuzzer, linking with libFuzzer and libexpat.a
$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    /src/parse_fuzzer.cc -o /out/expat_parse_fuzzer \
    -lfuzzer .libs/libexpat.a \
    $FUZZER_LDFLAGS
```

### build.sh Script Environment 

When build.sh script is executed, the following locations are available within the image:

| Path                   | Description
| ------                 | -----
| `/src/<some_dir>`      | Source code needed to build your library.
| `/usr/lib/libfuzzer.a` | Prebuilt libFuzzer library that need to be linked into all fuzzers (`-lfuzzer`).

You *must* use special compiler flags to build your library and fuzzers.
These flags are provided in following environment variables:

| Env Variable           | Description
| -------------          | --------
| `$CC`, `$CXX`, `$CCC`  | The C and C++ compiler binaries.
| `$CFLAGS`, `$CXXFLAGS` | C and C++ compiler flags.
| `$FUZZER_LDFLAGS`      | Linker flags for fuzzer binaries.

Many well-crafted build scripts will automatically use these variables. If not,
passing them manually to a build tool might be required.

See [Provided Environment Variables](../infra/base-images/base-libfuzzer/README.md#provided-environment-variables) section in 
`base-libfuzzer` image documentation for more details.

### Custom libFuzzer options for ClusterFuzz

By default ClusterFuzz will run your fuzzer without any options. You can specify
custom options by creating a `fuzzer_name.options` file next to a fuzzier in `/out`:

```
[libfuzzer]
max_len = 1024
```

[List of available options](http://llvm.org/docs/LibFuzzer.html#options)

At least `max_len` is highly recommended.

For out of tree fuzzers you will likely add options file using docker's
`COPY` directive and will copy it into output in build script. 

### Dictionaries

Dictionaries hugely improve fuzzer effectiveness for inputs with lots of similar
sequences of bytes. [libFuzzer documentation](http://llvm.org/docs/LibFuzzer.html#dictionaries)

Put your dict files in `/out` and specify them in .options file:

```
[libfuzzer]
dict = dictionary_name.dict
```

### Seed corpora

You can also pass a set of initial seed files to your fuzzers. This is typically
a set of valid inputs to the target function you are testing, and can improve
coverage significantly.

This can be done by zipping up these files, naming them
`fuzzer_name_seed_corpus.zip`, and placing them in `/out` in your build script.

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

Simply replace the the "git" entry with the correct git url for the library.

*Note*: only git is supported right now.

## Testing locally

Helper script can be used to build images and fuzzers. Non-script
version using docker commands directly is documented [here](building_running_fuzzers_external.md).

```bash
$ cd /path/to/oss-fuzz
$ python scripts/helper.py build_image $LIB_NAME
$ python scripts/helper.py build_fuzzers $LIB_NAME
```

This should place the built fuzzers into `/path/to/oss-fuzz/build/out/$LIB_NAME`
on your machine (`/out` in the container). You can then try to run these fuzzers
inside the container to make sure that they work properly:

```bash
$ python scripts/helper.py run_fuzzer $LIB_NAME name_of_a_fuzzer
```

If everything works locally, then it should also work on our automated builders
and ClusterFuzz.

It's recommended to look at coverage as a sanity check to make sure that fuzzer gets to the code you expect.

```bash
$ python scripts/helper.py coverage $LIB_NAME name_of_a_fuzzer
```

## Debugging Problems

[Debugging](debugging.md) document lists ways to debug your build scripts or fuzzers
in case you run into problems.

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
