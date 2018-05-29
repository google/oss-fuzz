# Ideal integration with OSS-Fuzz 
OSS projects have different build and test systems. So, we can not expect them
to have a unified way of implementing and maintaining fuzz targets and integrating
them with OSS-Fuzz. However, we will still try to give recommendations on the preferred ways.

Here are several features (starting from the easiest) that will make automated fuzzing
simple and efficient, and will allow to catch regressions early on in the development cycle. 

## TL;DR
Every [fuzz target](http://libfuzzer.info/#fuzz-target):
* Is [maintained by code owners](#fuzz-target) in their RCS (Git, SVN, etc).
* Is [built with the rest of the tests](#build-support) - no bit rot! 
* Has a [seed corpus](#seed-corpus) with good [code coverage](#coverage).
* Is [continuously tested on the seed corpus](#regression-testing) with [ASan/UBSan/MSan](https://github.com/google/sanitizers)
* Is [fast and has no OOMs](#performance)
* Has a [fuzzing dictionary](#fuzzing-dictionary), if applicable

## Fuzz Target
The code of the [fuzz target(s)](http://libfuzzer.info/#fuzz-target) should be part of the project's source code repository. 
All fuzz targets should be easily discoverable (e.g. reside in the same directory, or follow the same naming pattern, etc). 

This makes it easy to maintain the fuzzers and minimizes breakages that can arise as source code changes over time.

Make sure to fuzz the target locally for a small period of time to ensure that 
it does not crash, hang, or run out of memory instantly.
See details at http://libfuzzer.info and http://tutorial.libfuzzer.info.

The interface between the [fuzz target]((http://libfuzzer.info/#fuzz-target))
and the fuzzing engines is C, so you may use C or C++ to implement the fuzz target.

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

## Build support
A plethora of different build systems exist in the open-source world.
And the less OSS-Fuzz knows about them, the better it can scale.

An ideal build integration for OSS-Fuzz would look like this:
* For every fuzz target `foo` in the project, there is a build rule that builds `foo_fuzzer`,
a binary that contains the fuzzing entry point (`LLVMFuzzerTestOneInput`)
and all the code it depends on, and that uses the `main()` function from `$LIB_FUZZING_ENGINE`
(env var [provided](new_project_guide.md) by OSS-Fuzz environment).
* The build system supports changing the compiler and passing extra compiler
flags so that the build command for a `foo_fuzzer` looks similar to this:

```bash
# Assume the following env vars are set:
# CC, CXX, CFLAGS, CXXFLAGS, LIB_FUZZING_ENGINE
$ make_or_whatever_other_command foo_fuzzer
```

This will allow to have minimal OSS-Fuzz-specific configuration and thus be more robust.

There is no point in hardcoding the exact compiler flags in the build system because they
a) may change and b) are different depending on the fuzzing engine and the sanitizer being used.

## Seed Corpus
The *corpus* is a set of inputs for the fuzz target (stored as individual files). 
When starting the fuzzing process, one should have a "seed corpus", 
i.e. a set of inputs to "seed" the mutations.
The quality of the seed corpus has a huge impact on fuzzing efficiency as it allows the fuzzer
to discover new code paths more easily.

The ideal corpus is a minimal set of inputs that provides maximal code coverage. 

For better OSS-Fuzz integration, 
the seed corpus should be available in revision control (can be same or different as the source code). 
It should be regularly extended with the inputs that (used to) trigger bugs and/or touch new parts of the code. 

Examples: 
[boringssl](https://github.com/google/boringssl/tree/master/fuzz),
[openssl](https://github.com/openssl/openssl/tree/master/fuzz),
[nss](https://github.com/mozilla/nss-fuzzing-corpus) (corpus in a separate repo).

## Regression Testing
The fuzz targets should be regularly tested (not necessarily fuzzed!) as a part of the project's regression testing process.
One way to do so is to link the fuzz target with a simple standalone driver
(e.g. [this one](https://github.com/llvm-mirror/compiler-rt/tree/master/lib/fuzzer/standalone))
that runs the provided inputs and use this driver with the seed corpus created in previous step. 
It is recommended to use [sanitizers](https://github.com/google/sanitizers) during regression testing.

Examples: [SQLite](https://www.sqlite.org/src/artifact/d9f1a6f43e7bab45),
[openssl](https://github.com/openssl/openssl/blob/master/fuzz/test-corpus.c)

## Fuzzing dictionary
For some input types, a simple dictionary of tokens used by the input language
can have a dramatic positive effect on fuzzing efficiency. 
For example, when fuzzing an XML parser, a dictionary of XML tokens will help.
AFL has a [collection](https://github.com/rc0r/afl-fuzz/tree/master/dictionaries)
of such dictionaries for some of the popular data formats.
Ideally, a dictionary should be maintained alongside the fuzz target.
The syntax is described [here](http://libfuzzer.info/#dictionaries).

## Coverage
For a fuzz target to be useful, it must have good coverage in the code that it is testing. You can view the coverage
for your fuzz targets by looking at the [fuzzer stats](https://github.com/google/oss-fuzz/blob/master/docs/clusterfuzz.md#fuzzer-stats) dashboard on ClusterFuzz, as well as
[coverage reports](https://github.com/google/oss-fuzz/blob/master/docs/clusterfuzz.md#coverage-reports).

Coverage can often be improved by adding dictionaries, more inputs for seed corpora, and fixing
timeouts/out-of-memory bugs in your targets.

## Performance
Fuzz targets should also be performant, as high memory usage and/or slow execution speed can slow the down
the growth of coverage and finding of new bugs. ClusterFuzz provides a
[performance analyzer](https://github.com/google/oss-fuzz/blob/master/docs/clusterfuzz.md)
for each fuzz target that shows problems that are impacting the performance of the fuzz target.

## Example
You may look at a simple [example](../projects/example/my-api-repo) that covers most of the items above. 

## Not a project member?

If you are a member of the project you want to fuzz, most of the steps above are simple.
However in some cases, someone outside the project team may want to fuzz the code
and the project maintainers are not interested in helping.

In such cases, we can host the fuzz targets, dictionaries, etc in OSS-Fuzz's 
repository and mention them in the Dockerfile.
Examples: [libxml2](../projects/libxml2), [c-ares](../projects/c-ares), [expat](../projects/expat).
This is far from ideal because the fuzz targets will not be continuously tested 
and hence may quickly bitrot.

If you are not a project maintainer, we may not be able to CC you to security bugs found by OSS-Fuzz.
