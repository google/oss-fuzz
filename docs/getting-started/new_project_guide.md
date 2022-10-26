---
layout: default
title: Setting up a new project
parent: Getting started
has_children: true
nav_order: 2
permalink: /getting-started/new-project-guide/
---

# Setting up a new project
{: .no_toc}

- TOC
{:toc}
---

## Prerequisites

Before you can start setting up your new project for fuzzing, you must do the following:

- [Integrate]({{ site.baseurl }}/advanced-topics/ideal-integration/) one or more [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target)
  with the project you want to fuzz.

  For examples, see
[boringssl](https://github.com/google/boringssl/tree/master/fuzz) or
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338) (C/C++),
[go-fuzz](https://github.com/dvyukov/go-fuzz-corpus/tree/86a5af9d6842f80b205a082538ea28f61bbb8ccb) or
[syzkaller](https://github.com/google/syzkaller/tree/7c7ded697e6322b0975f061b7e268fe44f585dab/prog/test)
(Go).

- [Install Docker](https://docs.docker.com/engine/installation)
  (Googlers can visit [go/installdocker](https://goto.google.com/installdocker)).
  [Why Docker?]({{ site.baseurl }}/faq/#why-do-you-use-docker)

  If you want to run `docker` without `sudo`, you can
  [create a docker group](https://docs.docker.com/engine/installation/linux/ubuntulinux/#/create-a-docker-group).

  **Note:** Docker images can consume significant disk space. Run
  [docker-cleanup](https://gist.github.com/mikea/d23a839cba68778d94e0302e8a2c200f)
  periodically to garbage-collect unused images.

- (optional) [Install gsutil](https://cloud.google.com/storage/docs/gsutil_install) for local code coverage testing.
  For Google internal (gLinux) machines, please refer [here](https://cloud.google.com/storage/docs/gsutil_install#deb) instead.

## Creating the file structure

Each OSS-Fuzz project has a subdirectory
inside the [`projects/`](https://github.com/google/oss-fuzz/tree/master/projects) directory in the [OSS-Fuzz repository](https://github.com/google/oss-fuzz). For example, the [boringssl](https://github.com/google/boringssl)
project is located in [`projects/boringssl`](https://github.com/google/oss-fuzz/tree/master/projects/boringssl).

Each project directory also contains the following three configuration files:

* [project.yaml](#projectyaml) - provides metadata about the project.
* [Dockerfile](#dockerfile) - defines the container environment with information
on dependencies needed to build the project and its [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target).
* [build.sh](#buildsh) - defines the build script that executes inside the Docker container and
generates the project build.

You can automatically create a new directory for your project in OSS-Fuzz and
generate templated versions of the configuration files
by running the following commands:

```bash
$ cd /path/to/oss-fuzz
$ export PROJECT_NAME=<project_name>
$ export LANGUAGE=<project_language>
$ python infra/helper.py generate $PROJECT_NAME --language=$LANGUAGE
```

Once the template configuration files are created, you can modify them to fit your project.

**Note:** We prefer that you keep and maintain [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) in your own source code repository. If this isn't possible, you can store them inside the OSS-Fuzz project directory you created.

## project.yaml {#projectyaml}

This configuration file stores project metadata. The following attributes are supported:

- [homepage](#homepage)
- [language](#language)
- [primary_contact](#primary)
- [auto_ccs](#auto_ccs)
- [main_repo](#main_repo)
- [vendor_ccs](#vendor) (optional)
- [sanitizers](#sanitizers) (optional)
- [architectures](#architectures) (optional)
- [help_url](#help_url) (optional)
- [builds_per_day](#build_frequency) (optional)
- [file_github_issue](#file_github_issue) (optional)

### homepage
You project's homepage.

### language

Programming language the project is written in. Values you can specify include:

* `c`
* `c++`
* [`go`]({{ site.baseurl }}//getting-started/new-project-guide/go-lang/)
* [`rust`]({{ site.baseurl }}//getting-started/new-project-guide/rust-lang/)
* [`python`]({{ site.baseurl }}//getting-started/new-project-guide/python-lang/)
* [`jvm` (Java, Kotlin, Scala and other JVM-based languages)]({{ site.baseurl }}//getting-started/new-project-guide/jvm-lang/)
* [`swift`]({{ site.baseurl }}//getting-started/new-project-guide/swift/)

### primary_contact, auto_ccs {#primary}
The primary contact and list of other contacts to be CCed. Each person listed gets access to ClusterFuzz, including crash reports and fuzzer statistics, and are auto-cced on new bugs filed in the OSS-Fuzz
tracker. If you're a primary or a CC, you'll need to use a [Google account](https://support.google.com/accounts/answer/176347?hl=en) to get full access. ([why?]({{ site.baseurl }}/faq/#why-do-you-require-a-google-account-for-authentication)).

### main_repo {#main_repo}
Path to source code repository hosting the code, e.g. `https://path/to/main/repo.git`. 

### vendor_ccs (optional) {#vendor}
The list of vendor email addresses that are downstream consumers of the project and want access to
the bug reports as they are filed.

Any changes to this list must follow these rules:
- Approved by the project maintainer (e.g. comment on pull request, reply on project mailing list).
- An organization email address is used.

### sanitizers (optional) {#sanitizers}
The list of sanitizers to use. If you don't specify a list, `sanitizers` uses a default list of supported
sanitizers (currently ["address"](https://clang.llvm.org/docs/AddressSanitizer.html) and
["undefined"](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)).

[MemorySanitizer](https://clang.llvm.org/docs/MemorySanitizer.html) ("memory") is also supported
and recommended, but is not enabled by default due to the likelihood of false positives from
un-instrumented system dependencies.
If you want to use "memory," please build all libraries your project needs using
MemorySanitizer.
This can be done by building them with the compiler flags provided during
MemorySanitizer builds.
Then, you can opt in by adding "memory" to your list of sanitizers.

If your project does not build with a particular sanitizer configuration and you need some time to fix
it, you can use `sanitizers` to override the defaults temporarily. For example, to disable the
UndefinedBehaviourSanitizer build, just specify all supported sanitizers except "undefined".

If you want to test a particular sanitizer to see what crashes it generates without filing
them in the issue tracker, you can set an `experimental` flag. For example, if you want to test "memory", set `experimental: True` like this:

```
sanitizers:
 - address
 - memory:
    experimental: True
 - undefined
 ```

Crashes can be accessed on the [ClusterFuzz
homepage]({{ site.baseurl }}/further-reading/clusterfuzz#web-interface).

`sanitizers` example: [boringssl](https://github.com/google/oss-fuzz/blob/master/projects/boringssl/project.yaml).

### architectures (optional) {#architectures}
The list of architectures to fuzz on.
ClusterFuzz supports fuzzing on x86_64 (aka x64) by default.
Some projects can benefit from i386 fuzzing. OSS-Fuzz will build and run
AddressSanitizer with libFuzzer on i386 by doing the following:

```yaml
architectures:
 - x86_64
 - i386
 ```

By fuzzing on i386 you might find bugs that:
* Only occur in architecture-specific source code (e.g. code that contains i386 assembly).
* Exist in architecture-independent source code and which only affects i386 users.
* Exist in architecture-independent source code and which affects users on other 32-bit platforms such as AArch32 (aka 32-bit ARM).

Note that some bugs which affect x86_64 may be discovered on i386 and filed as such.
On the testcase page of each oss-fuzz issue is a list of other jobs where the crash reproduces, this can let you know if the crash exists on x86_64 as well.

Fuzzing on i386 is not enabled by default because many projects won't build for i386 without some modification to their OSS-Fuzz build process.
For example, you will need to link against `$LIB_FUZZING_ENGINE` and possibly install i386 dependencies within the x86_64 docker image ([for example](https://github.com/google/oss-fuzz/blob/5b8dcb5d942b3b8bc173b823fb9ddbdca7ec6c99/projects/gdal/build.sh#L18)) to get things working.

There are [known bugs](https://github.com/google/oss-fuzz/issues/2746) in ASAN
on i386 that cause ClusterFuzz to report unreproducible crashes for 0 length
testcases. There are no plans to fix these bugs so be ready for slightly more
false positives if you use i386. These false positives should be somewhat easy
to identify since they will manifest as crashes in ASAN rather than your code.

### fuzzing_engines (optional) {#fuzzing_engines}
The list of fuzzing engines to use.
By default, `libfuzzer`, `afl`, `honggfuzz`, and `centipede` are used. It is recommended to
use all of them if possible. `libfuzzer` is required by OSS-Fuzz.

### help_url (optional) {#help_url}
A link to a custom help URL that appears in bug reports instead of the default
[OSS-Fuzz guide to reproducing crashes]({{ site.baseurl }}/advanced-topics/reproducing/). This can be useful if you assign
bugs to members of your project unfamiliar with OSS-Fuzz, or if they should follow a different workflow for
reproducing and fixing bugs than the standard one outlined in the reproducing guide.

`help_url` example: [skia](https://github.com/google/oss-fuzz/blob/master/projects/skia/project.yaml).

### builds_per_day (optional) {#build_frequency}
The number of times the project should be built per day.
OSS-Fuzz allows upto 4 builds per day, and builds once per day by default.
Example:
```yaml
builds_per_day: 2
```

Will build the project twice per day.

### file_github_issue (optional) {#file_github_issue}
Whether to mirror issues on github instead of having them only in the OSS-Fuzz
tracker.

## Dockerfile {#dockerfile}

This configuration file defines the Docker image for your project. Your [build.sh](#buildsh) script will be executed in inside the container you define.
For most projects, the image is simple:
```docker
FROM gcr.io/oss-fuzz-base/base-builder       # base image with clang toolchain
RUN apt-get update && apt-get install -y ... # install required packages to build your project
RUN git clone <git_url> <checkout_dir>       # checkout all sources needed to build your project
WORKDIR <checkout_dir>                       # current directory for the build script
COPY build.sh fuzzer.cc $SRC/                # copy build script and other fuzzer files in src dir
```
In the above example, the git clone will check out the source to `$SRC/<checkout_dir>`.

Depending on your project's language, you will use a different base image,
for instance `FROM gcr.io/oss-fuzz-base/base-builder-go` for golang.

For an example, see
[expat/Dockerfile](https://github.com/google/oss-fuzz/tree/master/projects/expat/Dockerfile)
or
[syzkaller/Dockerfile](https://github.com/google/oss-fuzz/blob/master/projects/syzkaller/Dockerfile).

In the case of a project with multiple languages/toolchains needed,
you can run installation scripts `install_lang.sh` where lang is the language needed.
You also need to setup environment variables needed by this toolchain, for example `GOPATH` is needed by golang.
For an example, see
[ecc-diff-fuzzer/Dockerfile](https://github.com/google/oss-fuzz/blob/master/projects/ecc-diff-fuzzer/Dockerfile).
where we use `base-builder-rust`and install golang

## build.sh {#buildsh}

This file defines how to build binaries for [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) in your project.
The script is executed within the image built from your [Dockerfile](#Dockerfile).

In general, this script should do the following:

- Build the project using your build system with the correct compiler.
- Provide compiler flags as [environment variables](#Requirements).
- Build your [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) and link your project's build with libFuzzer.

Resulting binaries should be placed in `$OUT`.

Here's an example from Expat ([source](https://github.com/google/oss-fuzz/blob/master/projects/expat/build.sh)):

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

1. Don't assume the fuzzing engine is libFuzzer by default, because we generate builds for libFuzzer, AFL++, Honggfuzz, and Centipede fuzzing engine configurations. Instead, link the fuzzing engine using $LIB_FUZZING_ENGINE.
2. Make sure that the binary names for your [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) contain only
alphanumeric characters, underscore(_) or dash(-). Otherwise, they won't run on our infrastructure.
3. Don't remove source code files. They are needed for code coverage.

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

### Static and dynamic linking of libraries
The `build.sh` should produce fuzzers that are statically linked. This is because the
fuzzer build environment is different to the fuzzer runtime environment and if your
project depends on third party libraries then it is likely they will not be present
in the execution environment. Thus, any shared libraries you may install or compile in
`build.sh` or `Dockerfile` will not be present in the fuzzer runtime environment. There
are exceptions to this rule, and for further information on this please see the [fuzzer environment]({{ site.baseurl }}/further-reading/fuzzer-environment/) page.

## Disk space restrictions

Our builders have a disk size of 250GB (this includes space taken up by the OS). Builds must keep peak disk usage below this.

In addition, please keep the size of the build (everything copied to `$OUT`) small (<10GB uncompressed). The build is repeatedly transferred and unzipped during fuzzing and runs on VMs with limited disk space.

## Fuzzer execution environment

For more on the environment that
your [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target) run in, and the assumptions you can make, see the [fuzzer environment]({{ site.baseurl }}/further-reading/fuzzer-environment/) page.

## Testing locally

You can build your docker image and fuzz targets locally, so you can test them before you push them to the OSS-Fuzz repository.

1. Run the same helper script you used to create your directory structure, this time using it to build your docker image and [fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target):

    ```bash
    $ cd /path/to/oss-fuzz
    $ python infra/helper.py build_image $PROJECT_NAME
    $ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> $PROJECT_NAME
    ```

    The built binaries appear in the `/path/to/oss-fuzz/build/out/$PROJECT_NAME`
    directory on your machine (and `$OUT` in the container).

    **Note:** You *must* run your fuzz target binaries inside the base-runner docker
    container to make sure that they work properly.

2. Find failures to fix by running the `check_build` command:

    ```bash
    $ python infra/helper.py check_build $PROJECT_NAME
    ```

3. If you want to test changes against a particular fuzz target, run the following command:

    ```bash
    $ python infra/helper.py run_fuzzer --corpus-dir=<path-to-temp-corpus-dir> $PROJECT_NAME <fuzz_target>
    ```

4. We recommend taking a look at your code coverage as a test to ensure that
your fuzz targets get to the code you expect. This would use the corpus
generated from the previous `run_fuzzer` step in your local corpus directory.

    ```bash
    $ python infra/helper.py build_fuzzers --sanitizer coverage $PROJECT_NAME
    $ python infra/helper.py coverage $PROJECT_NAME --fuzz-target=<fuzz_target> --corpus-dir=<path-to-temp-corpus-dir>
    ```

You may need to run `python infra/helper.py pull_images` to use the latest
coverage tools. Please refer to
[code coverage]({{ site.baseurl }}/advanced-topics/code-coverage/) for detailed
information on code coverage generation.


**Note:** Currently, we only support AddressSanitizer (address) and UndefinedBehaviorSanitizer (undefined)
configurations by default.
MemorySanitizer is recommended, but needs to be enabled manually since you must build all runtime dependencies with MemorySanitizer.
<b>Make sure to test each
of the supported build configurations with the above commands (build_fuzzers -> run_fuzzer -> coverage).</b>

If everything works locally, it should also work on our automated builders and ClusterFuzz. If you check in
your files and experience failures, review your [dependencies]({{ site.baseurl }}/further-reading/fuzzer-environment/#dependencies).

## Debugging Problems

If you run into problems, our [Debugging page]({{ site.baseurl }}/advanced-topics/debugging/) lists ways to debug your build scripts and
[fuzz targets]({{ site.baseurl }}/reference/glossary/#fuzz-target).

## Efficient fuzzing

To improve your fuzz target ability to find bugs faster, you should consider the
following ways:

### Seed Corpus

Most fuzzing engines use evolutionary fuzzing algorithms. Supplying a seed
corpus consisting of good sample inputs is one of the best ways to improve [fuzz
target]({{ site.baseurl }}/reference/glossary/#fuzz-target)'s coverage.

To provide a corpus for `my_fuzzer`, put `my_fuzzer_seed_corpus.zip` file next
to the [fuzz target]({{ site.baseurl }}/reference/glossary/#fuzz-target)'s binary in `$OUT` during the build. Individual files in this
archive will be used as starting inputs for mutations. You can store the corpus
next to source files, generate during build or fetch it using curl or any other
tool of your choice.
(example: [boringssl](https://github.com/google/oss-fuzz/blob/master/projects/boringssl/build.sh#L41)).

Seed corpus files will be used for cross-mutations and portions of them might appear
in bug reports or be used for further security research. It is important that corpus
has an appropriate and consistent license.

OSS-Fuzz only: See also [Accessing Corpora]({{ site.baseurl }}/advanced-topics/corpora/) for information about getting access to the corpus we are currently using for your fuzz targets.

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
(example: [expat](https://github.com/google/oss-fuzz/blob/ad88a2e5295d91251d15f8a612758cd9e5ad92db/projects/expat/parse_fuzzer.options)).

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

## Checking in to the OSS-Fuzz repository

Once you've tested your fuzzing files locally, fork OSS-Fuzz, commit, and push to the fork. Then
create a pull request with your change. Follow the
[Forking Project](https://guides.github.com/activities/forking/) guide if you're new to contributing
via GitHub.

### Copyright headers

Please include copyright headers for all files checked in to oss-fuzz:

```
# Copyright 2021 Google LLC
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

**Exception:** If you're porting a fuzz target from Chromium, keep the original Chromium license header.

## Reviewing results

Once your change is merged, your project and fuzz targets should be automatically built and run on
ClusterFuzz after a short while (&lt; 1 day). If you think there's a problem, you can check your project's [build status](https://oss-fuzz-build-logs.storage.googleapis.com/index.html).

Use the [ClusterFuzz web interface](https://oss-fuzz.com/) to review the following:
* Crashes generated
* Code coverage statistics
* Fuzzer statistics
* Fuzzer performance analyzer (linked from fuzzer statistics)

**Note:** Your Google Account must be listed in [project.yaml](#projectyaml) for you to have access to the ClusterFuzz web interface.

### Status Badge

![Example
Badge](https://oss-fuzz-build-logs.storage.googleapis.com/badges/curl.svg)

Once your project has started [building](https://oss-fuzz-build-logs.storage.googleapis.com/index.html), we'd love it if you added our badge in
your project's README. This allows you to see bugs found by your OSS-Fuzz
integration at a glance. See
[brotli](https://github.com/google/brotli#introduction)'s
README for an example.

Adding it is super easy, just follow this template:
```markdown
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/<project>.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:<project>)
```

## Monitoring performance via Fuzz Introspector

As soon as your project is run with ClusterFuzz (< 1 day), you can view the Fuzz
Introspector report for your project.
[Fuzz Introspector](https://github.com/ossf/fuzz-introspector) helps you
understand your fuzzers' performance and identify any potential blockers.
It provides individual and aggregated fuzzer reachability and coverage reports.
You can monitor each fuzzer's static reachability potential and compare it
against dynamic coverage and identify any potential bottlenecks.
Fuzz Introspector can offer suggestions on increasing coverage by adding new
fuzz targets or modify existing ones.
Fuzz Introspector reports can be viewed from the [OSS-Fuzz
homepage](https://oss-fuzz.com/) or through this
[index](http://oss-fuzz-introspector.storage.googleapis.com/index.html).
Fuzz Introspector support C and C++ projects.
Support for Java and Python projects is in the progress.

You can view the [Fuzz Introspector report for bzip2](https://storage.googleapis.com/oss-fuzz-introspector/bzip2/inspector-report/20221017/fuzz_report.html)
as an example.
