---
layout: default
title: Glossary
nav_order: 1
permalink: /reference/glossary/
parent: Reference
---

# Glossary

For general fuzzing terms, see the [glossary] from [google/fuzzing] project.

[glossary]: https://github.com/google/fuzzing/blob/master/docs/glossary.md
[google/fuzzing]: https://github.com/google/fuzzing

- TOC
{:toc}
---

## OSS-Fuzz specific terms

### ClusterFuzz

A scalable fuzzing infrastructure that is used for OSS-Fuzz backend.
[ClusterFuzz] is also used to fuzz Chrome and many other projects. A quick
overview of ClusterFuzz user interface is available on this [page].

[page]: {{ site.baseurl }}/further-reading/clusterfuzz
[ClusterFuzz]: https://github.com/google/clusterfuzz

### Fuzz Target

In addition to its
[general definition](https://github.com/google/fuzzing/blob/master/docs/glossary.md#fuzz-target),
in OSS-Fuzz a fuzz target can be used to
[reproduce bug reports]({{ site.baseurl }}/advanced-topics/reproducing/).
It is recommended to use it for regression testing as well (see
[ideal integration]({{ site.baseurl }}/advanced-topics/ideal-integration/)).

### Job type

Or **Fuzzer Build**.

This refers to a build that contains all the [fuzz targets] for a given
[project](#project), is run with a specific [fuzzing engine], in a specific
build mode (e.g. with enabled/disabled assertions), and optionally combined
with a [sanitizer].

For example, we have a "libfuzzer_asan_sqlite" job type, indicating a build of
all sqlite3 [fuzz targets] using [libFuzzer](http://libfuzzer.info) and
[ASan](http://clang.llvm.org/docs/AddressSanitizer.html).

### Project

A project is an open source software project that is integrated with OSS-Fuzz.
Each project has a single set of configuration files 
(example: [expat](https://github.com/google/oss-fuzz/tree/master/projects/expat))
and may have one or more [fuzz targets]
(example: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/)).

### Reproducer

Or a **testcase**.

A [test input] that causes a specific bug to reproduce.

[fuzz targets]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#fuzz-target
[fuzzing engine]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#fuzzing-engine
[sanitizer]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#sanitizer
[test input]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#test-input

### Sanitizers

Fuzzers are usually built with one or more [sanitizer](https://github.com/google/sanitizers) enabled. 

```bash
$ python infra/helper.py build_fuzzers --sanitizer undefined json
```

Supported sanitizers:

| Sanitizer | Description
| ------------ | ----------
| `address` *(default)* | [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer) with [Leak Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer).
| `undefined` | [Undefined Behavior Sanitizer](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
| `memory` | [Memory Sanitizer](https://github.com/google/sanitizers/wiki/MemorySanitizer).<br/>*NOTE: It is critical that you build __all__ the code in your program (including libraries it uses) with Memory Sanitizer. Otherwise, you will see false positive crashes due to an inability to see initializations in uninstrumented code.*
| `coverage` | Used for generating code coverage reports. See [Code Coverage doc]({{ site.baseurl }}/advanced-topics/code-coverage/).

Compiler flag values for predefined configurations are specified in the [Dockerfile](https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/Dockerfile). 
These flags can be overridden by specifying `$SANITIZER_FLAGS` directly.

You can choose which configurations to automatically run your fuzzers with in `project.yaml` file (e.g. [sqlite3](https://github.com/google/oss-fuzz/tree/master/projects/sqlite3/project.yaml)).

### Architectures
ClusterFuzz supports fuzzing on x86_64 (aka x64) by default. However you can also fuzz using AddressSanitizer and libFuzzer on i386 (aka x86, or 32 bit) by specifying the `$ARCHITECTURE` build environment variable using the `--architecture` option:

```bash
python infra/helper.py build_fuzzers --architecture i386 json
```
