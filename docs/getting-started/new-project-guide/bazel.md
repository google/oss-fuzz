---
layout: default
title: Integrating a Bazel project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 4
permalink: /getting-started/new-project-guide/bazel/
---

# Integrating a Bazel project
{: .no_toc}

- TOC
{:toc}
---

## Bazel projects

The process of integrating a project using the [Bazel](https://bazel.build/)
build system with OSS-Fuzz is very similar to the general
[Setting up a new project]({{ site.baseurl }}/getting-started/new-project-guide/)
process. The key specifics of integrating a Bazel project are outlined below.

## Fuzzing support in Bazel

For Bazel-based projects, we recommend using the
[`rules_fuzzing`](https://github.com/bazelbuild/rules_fuzzing) extension library
for defining fuzz tests. `rules_fuzzing` provides support for building and running
fuzz tests under
[multiple sanitizer and fuzzing engine configurations][rules-fuzzing-usage].
It also supports specifying corpora and dictionaires as part of the fuzz test
definition.

The fuzzing rules provide out-of-the-box support for building and packaging fuzz
test artifacts in the OSS-Fuzz format. Each `//path/to:fuzz_test` fuzz test
target automatically has a `//path/to:fuzz_test_oss_fuzz` packaging target that
(a) builds the fuzz test using the instrumentation and engine library specified
in the OSS-Fuzz environment variables, and (b) generates an archive containing
the binary and its associated artifacts (corpus, dictionary, etc.). Using the
`_oss_fuzz` target substantially simplifies the `build.sh` script, which only
needs to copy the build artifacts from `bazel-bin/` to the `${OUT}/` directory.
The next section explains this process in more detail.

[rules-fuzzing-usage]: https://github.com/bazelbuild/rules_fuzzing#using-the-rules-in-your-project

## Project files

This section explains how to integrate the fuzz tests written using the
`rules_fuzzing` library with OSS-Fuzz. You can also see a complete example in the
[`bazel-rules-fuzzing-test`](https://github.com/google/oss-fuzz/tree/master/projects/bazel-rules-fuzzing-test)
project.

The structure of the project directory in the OSS-Fuzz repository does not
differ for Bazel-based projects. The project files have the following specific
aspects.

### project.yaml

Only C++ projects are currently supported.

Since the OSS-Fuzz target builds the fuzz test using the instrumentation and
engine specified in the OSS-Fuzz environment variables, all the engine and
sanitizer configurations supported in the `project.yaml` file are automatically
supported by the `_oss_fuzz` packaging rule, too.

### Dockerfile

There is no need to install Bazel in your Docker image. The OSS-Fuzz builder
image provides the `bazel` executable through the
[Bazelisk](https://github.com/bazelbuild/bazelisk) launcher, which will fetch
and use the latest Bazel release. If your project requires a particular Bazel
version, create a
[`.bazelversion`](https://docs.bazel.build/versions/master/updating-bazel.html)
file in your repository root with the desired version string.

### build.sh

Your `build.sh` script essentially needs to perform three tasks: (1) selecting
which fuzz tests to build, (2) building their OSS-Fuzz package targets in the
right configuration, and (3) copying the build artifacts to the `${OUT}/`
destination.

For the first step, you can use the "bazel query" command for the most
flexibility. Each fuzz test has the `"fuzz-test"` tag, which you can query. You
may also perform additional filtering. We recommend using the `"no-oss-fuzz"`
tag to opt-out particular fuzz tests if they are a work in progress or
test-only.

The complete query command would look as follows ([example][example-query]):

```sh
declare -r QUERY='
    let all_fuzz_tests = attr(tags, "fuzz-test", "//...") in
    $all_fuzz_tests - attr(tags, "no-oss-fuzz", $all_fuzz_tests)
'
declare -r OSS_FUZZ_TESTS="$(bazel query "${QUERY}" | sed "s/$/_oss_fuzz/")"
```

Building the `_oss_fuzz` targets requires setting the engine and instrumentation
options. We recommend creating a `--config=oss-fuzz` configuration in your
`.bazelrc` file ([example][example-bazelrc]), so you can directly invoke
`bazel build --config=oss-fuzz` in your build script ([example][example-build]).

If all goes well, `bazel-bin/` will contain an `_oss_fuzz.tar` archive for each
fuzz test built. You need to traverse each archive and extract it in the
`${OUT}/` directory ([example][example-copy]):

```sh
for oss_fuzz_archive in $(find bazel-bin/ -name '*_oss_fuzz.tar'); do
    tar -xvf "${oss_fuzz_archive}" -C "${OUT}"
done
```

[example-query]: https://github.com/google/oss-fuzz/blob/b19e7001928b08f9ae8fd3c017688cd5edf96cb2/projects/bazel-rules-fuzzing-test/build.sh#L27-L37
[example-bazelrc]: https://github.com/bazelbuild/rules_fuzzing/blob/f6062a88d83463e2900e47bc218547ba046dad44/.bazelrc#L56-L58
[example-build]: https://github.com/google/oss-fuzz/blob/b19e7001928b08f9ae8fd3c017688cd5edf96cb2/projects/bazel-rules-fuzzing-test/build.sh#L43-L45
[example-copy]: https://github.com/google/oss-fuzz/blob/b19e7001928b08f9ae8fd3c017688cd5edf96cb2/projects/bazel-rules-fuzzing-test/build.sh#L50-L52
