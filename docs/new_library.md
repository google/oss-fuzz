# Setting up fuzzers for a new library

Fuzzer build configurations are placed into a top-level directory for the
library in the [oss-fuzz repo] on GitHub. For example, fuzzers for the expat
library go into <https://github.com/google/oss-fuzz/tree/master/expat>.

## Prerequisites

[Install Docker].

If you're not familiar with how building libFuzzer-style fuzzers work in
general, check out [this page](http://llvm.org/docs/LibFuzzer.html).

## Library directories

A library directory requires 3 files:

* Jenkinsfile
* Dockerfile
* build.sh

To create a new directory for a library:

```bash
export LIB_NAME=name_of_the_library
cd /path/to/oss-fuzz/checkout
mkdir $LIB_NAME; cd $LIB_NAME
```

### Jenkinsfile

This file will be largely the same for most libraries. For expat, this is:

```
def libfuzzerBuild = fileLoader.fromGit('infra/libfuzzer-pipeline.groovy',
                                        'https://github.com/google/oss-fuzz.git',
                                        'master', null, '')

libfuzzerBuild {
  git = "git://git.code.sf.net/p/expat/code_git"
}
```

Simply replace the the "git" entry with the correct git url for the library.

*Note*: only git is supported right now.

### Dockerfile

This is the definition for the Docker container that fuzzers will be built in.
This should be very similar for most libraries as well. This file requires a
couple of lines:

* `FROM ossfuzz/base-libfuzzer` to inherit settings from the base container.
  Containers are based on Ubuntu 16.04.
* `MAINTAINER YOUR_EMAIL`
* `RUN ....` to run custom commands. For example, if your library requires
  additional build dependencies, you should include `apt-get` commands here to
  install them.
* `CMD /src/oss-fuzz/$LIB_NAME/build.sh` to run the custom build script for your
  library (see next section).

expat example:

```
FROM ossfuzz/base-libfuzzer
MAINTAINER mike.aizatsky@gmail.com
RUN apt-get install -y make autoconf automake libtool docbook2x

CMD /src/oss-fuzz/expat/build.sh
```

### build.sh

This is where most of the work is done to build fuzzers for your library.

When this script is run, the source code for your library will be at
`/src/$LIB_NAME`. The `oss-fuzz` repository will similarly be checked out to
`/src/oss-fuzz`.

`/work/libfuzzer` contains the libFuzzer object files that need to be linked
into all fuzzers.

Some useful environment variables are also set:

* `CC`: The C compiler.
* `CXX` or `CCC`: The C++ compiler.
* `CFLAGS`: Predefined C flags. This should always be passed when building
  fuzzers written in C.
* `CXXFLAGS`: Predefined C++ flags. This should always be passed when building
  fuzzers written in C++.
* `LDFLAGS`: Linker flags. This should always be passed when building
  fuzzer.

In general, this script will need to:

1. Build the library using whatever build system the library is using.
2. Build the fuzzers, linking with the library and libFuzzer. Built fuzzers
   should be placed in `/out`.

For expat, this looks like:

```bash
#!/bin/bash -eu

# cd into the expat directory.
cd /src/expat/expat

# build the library.
./buildconf.sh
./configure
make clean all

# build the fuzzer, linking with libFuzzer and libexpat.a
$CXX $CXXFLAGS -std=c++11 -Ilib/ \
    /src/oss-fuzz/expat/parse_fuzzer.cc -o /out/expat_parse_fuzzer \
    /work/libfuzzer/*.o .libs/libexpat.a $LDFLAGS
```

Breaking this down:

1. `cd /src/expat/expat` just changes the working directory to the expat dir.
2. `buildconfig.sh ... make clean all` calls the build system for the library
   (we need `libexpat.a`).
3. Build the fuzzer. In this case, we're building a fuzzer that's stored in the
   oss-fuzz repo (`/src/oss-fuzz/expat/parse_fuzzer.cc`), writing it to
   `/out/expat_parse_fuzzer`, and linking in `/work/libfuzzer/*.o` (prebuilt)
   and `.libs/libexpat.a` (which we just built).


### Dictionaries and custom libfuzzer options

Any top-level files in the library directory ending with the extension ".dict"
or ".options" will be picked up by ClusterFuzz. Files ending with ".dict" are
assumed to be libFuzzer compatible [dictionaries], and .options files have the
format:

```
[libfuzzer]
dict = dictionary_name.dict
max_len = 9001
```

This means that `-dict=/path/to/dictionary_name.dict` and `-max_len=9001` will
be passed to the fuzzer when it's run.

### Others (e.g. fuzzer source)

For some libraries, the upstream repository will contain fuzzers (e.g.
freetype2). In other cases, such as expat, we can check in fuzzer source into
the oss-fuzz repo.

## Testing locally

```bash
$ mkdir ~/src; cd ~/src
$ git clone https://github.com/google/oss-fuzz
# Also checkout upstream library, make sure the directory name is the same
# as $LIB_NAME.
# For expat:
# git clone git://git.code.sf.net/p/expat/code_git $LIB_NAME

$ cd oss-fuzz
# (patch in your changes to oss-fuzz )

$ docker build -t ossfuzz/$LIB_NAME $LIB_NAME
$ docker run -i -v ~/src/oss-fuzz:/src/oss-fuzz -v ~/src/$LIB_NAME:/src/$LIB_NAME -v ~/tmp/out:/out -t ossfuzz/$LIB_NAME
```

This should place the built fuzzers into `~/tmp/out` on your machine (`/out` in
the container). You can then try to run these fuzzers inside the container to
make sure that they work properly:

```bash
$ docker run -i -v ~/tmp/out:/out -t ossfuzz/libfuzzer-runner /out/FUZZER_NAME
```

If everything works locally, then it should also work on our automated builders
and ClusterFuzz.

## Checking in to oss-fuzz repository

Fork oss-fuzz, commit and push to the fork, and then create a pull request with
your change!

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
