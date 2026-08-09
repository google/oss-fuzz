---
layout: default
title: Integrating a Bazel project
parent: Setting up a new project
grand_parent: Getting started
nav_order: 5
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
It also supports specifying corpora and dictionaries as part of the fuzz test
definition.

The fuzzing rules provide out-of-the-box support for building and packaging fuzz
test artifacts in the OSS-Fuzz format. Each `//path/to:fuzz_test` fuzz test
target automatically has a `//path/to:fuzz_test_oss_fuzz` packaging target that
(a) builds the fuzz test using the instrumentation and engine library specified
in the OSS-Fuzz environment variables, and (b) generates an archive containing
the binary and its associated artifacts (corpus, dictionary, etc.). Moreover,
OSS-Fuzz provides a standard tool to automatically process these targets,
substantially simplifying the `build.sh` script (see below).

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
supported by the fuzzing rules.

### Dockerfile

There is no need to install Bazel in your Docker image. The OSS-Fuzz builder
image provides the `bazel` executable through the
[Bazelisk](https://github.com/bazelbuild/bazelisk) launcher, which will fetch
and use the latest Bazel release. If your project requires a particular Bazel
version, create a
[`.bazelversion`](https://docs.bazel.build/versions/master/updating-bazel.html)
file in your repository root with the desired version string.

### build.sh

Your `build.sh` script essentially needs to perform three steps: (1) selecting
which fuzz tests to build, (2) building their OSS-Fuzz package targets in the
right configuration, and (3) copying the build artifacts to the `${OUT}/`
destination.

OSS-Fuzz provides a
[`bazel_build_fuzz_tests`](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/bazel_build_fuzz_tests)
tool that implements these steps in a standard way, so in most cases your
build script only needs to invoke this command with no arguments.

If necessary, the behavior of the tool can be customized through a set of
environment variables. The most common are:

* `BAZEL_EXTRA_BUILD_FLAGS` are extra build flags passed on the Bazel command
   line.
* `BAZEL_FUZZ_TEST_TAG` and `BAZEL_FUZZ_TEST_EXCLUDE_TAG` can be overridden to
  specify which target tags to use when determining what fuzz tests to include.
  By default, the tool selects all the fuzz tests except for those tagged as
  `"no-oss-fuzz"`.
* `BAZEL_FUZZ_TEST_QUERY` overrides the Bazel query the tool uses to identify
  the fuzz tests to build, if the tag-based approach is not sufficient.
