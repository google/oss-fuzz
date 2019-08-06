# Glossary

For general fuzzing terms, see the [glossary] from [google/fuzzing] project,

[glossary]: https://github.com/google/fuzzing/blob/master/docs/glossary.md
[google/fuzzing]: https://github.com/google/fuzzing

## OSS-Fuzz specific terms

### ClusterFuzz

A scalable fuzzing infrastructure that is used for OSS-Fuzz backend.
[ClusterFuzz] is also used to fuzz Chrome and many other projects. A quick
overview of ClusterFuzz user interface is available on this [page].

[page]: clusterfuzz.md
[ClusterFuzz]: https://github.com/google/clusterfuzz

### Fuzz Target

In addition to its general definition, in OSS-Fuzz a fuzz target can be used to
[reproduce bug reports](reproducing.md). It is recommended to use it for
regression testing as well (see [ideal integration](ideal_integration.md)).

### Job type

Or **Fuzzer Build**.

This refers to a build that contains all the [fuzz targets] for a given
[project](#project), is run  with a specific [fuzzing engine], in a specific
build mode (e.g. with enabled/disabled assertions),  and optionally combined
with a [sanitizer].

For example, we have a "libfuzzer_asan_sqlite" job type, indicating a build of
all sqlite3 [fuzz targets] using  [libFuzzer](http://libfuzzer.info) and
[ASan](http://clang.llvm.org/docs/AddressSanitizer.html).

### Project

A project is an open source software project that is integrated with OSS-Fuzz.
Each project has a single set of configuration files 
(example: [expat](https://github.com/google/oss-fuzz/tree/master/projects/expat))
and  may have one or more [fuzz targets]
(example: [openssl](https://github.com/openssl/openssl/blob/master/fuzz/)). 

### Reproducer

Or a **testcase**.

A [test input] that causes a specific bug to reproduce.

[fuzz targets]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#fuzz-target
[fuzzing engine]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#fuzzing-engine
[sanitizer]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#sanitizer
[test input]: https://github.com/google/fuzzing/blob/master/docs/glossary.md#test-input
