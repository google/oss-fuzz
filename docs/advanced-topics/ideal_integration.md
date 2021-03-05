---
layout: default
title: Ideal integration
parent: Advanced topics
nav_order: 1
permalink: /advanced-topics/ideal-integration/
---

# Ideal integration with OSS-Fuzz
{: .no_toc}

OSS projects have different build and test systems. We can't expect them all to
implement and maintain fuzz targets or integrate them with OSS-Fuzz in the same
way. However, we do have recommendations.

This page documents several features (starting from the easiest) that will make
automated fuzzing simple and efficient, and will help you catch regressions
early in the development cycle. This simple
[example](https://github.com/google/oss-fuzz/tree/master/projects/example/my-api-repo)
covers most of the items. 

- TOC
{:toc}
---

## Summary

Every [fuzz target](http://libfuzzer.info/#fuzz-target):
* Is [maintained by code owners](#fuzz-target) in their RCS (Git, SVN, etc).
* Is [built with the rest of the tests](#build-support) - no bit rot! 
* Has a [seed corpus](#seed-corpus) with good [code coverage](#coverage).
* Has a [dictionary](#dictionary), if applicable.
* Is [continuously tested on the seed corpus](#regression-testing) with
  [ASan/UBSan/MSan](https://github.com/google/sanitizers).
* Is [fast and has no OOMs](#performance).

## Fuzz Target

The code of the [fuzz target(s)](http://libfuzzer.info/#fuzz-target) should be
part of the project's source code repository.  All fuzz targets should be easily
discoverable (reside in the same directory, follow the same naming pattern,
etc.). 

This makes it easy to maintain the fuzzers and minimizes breakages that can
arise as source code changes over time.

Make sure to fuzz the target locally for a small period of time to ensure that 
it does not crash, hang, or run out of memory instantly. If you're having
trouble, read about [what makes a good fuzz
target](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md).

The interface between the [fuzz target]((http://libfuzzer.info/#fuzz-target))
and the fuzzing engines is C, so you can use either C or C++ to implement the
fuzz target.

Examples: 
[boringssl](https://github.com/google/boringssl/tree/master/fuzz),
[SQLite](https://www.sqlite.org/src/artifact/ad79e867fb504338),
[s2n](https://github.com/awslabs/s2n/tree/master/tests/fuzz),
[openssl](https://github.com/openssl/openssl/tree/master/fuzz),
[FreeType](http://git.savannah.gnu.org/cgit/freetype/freetype2.git/tree/src/tools/ftfuzzer),
[re2](https://github.com/google/re2/tree/master/re2/fuzzing),
[harfbuzz](https://github.com/behdad/harfbuzz/tree/master/test/fuzzing),
[pcre2](https://vcs.pcre.org/pcre2/code/trunk/src/pcre2_fuzzsupport.c?view=markup),
[ffmpeg](https://github.com/FFmpeg/FFmpeg/blob/master/tools/target_dec_fuzzer.c).

## Build support

Many different build systems exist in the open-source world. The less OSS-Fuzz
knows about them, the better it can scale.

An ideal build integration for OSS-Fuzz looks like this:
* For every fuzz target `foo` in the project, there is a build rule that
builds `foo_fuzzer`, a binary that: 
	* Contains the fuzzing entry point.
	* Contains (`LLVMFuzzerTestOneInput`) and all the code it depends on.
	* Uses the `main()` function from `$LIB_FUZZING_ENGINE` (env var [provided]({{ site.baseurl }}/getting-started/new-project-guide/) by OSS-Fuzz environment).
* Since the build system supports changing the compiler and passing extra compiler
flags, the build command for `foo_fuzzer` looks similar to this:

```bash
# Assume the following env vars are set:
# CC, CXX, CFLAGS, CXXFLAGS, LIB_FUZZING_ENGINE
$ make_or_whatever_other_command foo_fuzzer
```

This minimizes OSS-Fuzz-specific configuration, making your fuzzing more robust.

There is no point in hardcoding the exact compiler flags in the build system
because they a) may change and b) depend on the fuzzing engine and sanitizer
being used.

## Seed Corpus

The *seed corpus* is a set of test inputs, stored as individual files, provided
to the fuzz target as a starting point (to "seed" the mutations). The quality of
the seed corpus has a huge impact on fuzzing efficiency; the higher the quality,
the easier it is for the fuzzer to discover new code paths. The ideal corpus is
a minimal set of inputs that provides maximal code coverage. 

For better OSS-Fuzz integration,  the seed corpus should be available in
revision control (it can be the same as or different from the source code). It
should be regularly extended with the inputs that (used to) trigger bugs and/or
touch new parts of the code. 

Examples: 
[boringssl](https://github.com/google/boringssl/tree/master/fuzz),
[openssl](https://github.com/openssl/openssl/tree/master/fuzz),
[nss](https://github.com/mozilla/nss-fuzzing-corpus) (corpus in a separate repo).

## Dictionary

For some input types, a simple dictionary of tokens used by the input language
can have a dramatic impact on fuzzing efficiency.  For example, when fuzzing an
XML parser, a dictionary of XML tokens is helpful. AFL++ has a
[collection](https://github.com/AFLplusplus/AFLplusplus/tree/master/dictionaries)
of dictionaries for popular data formats. Ideally, a dictionary should be
maintained alongside the fuzz target, and it must use [correct
syntax](http://libfuzzer.info/#dictionaries).

## Coverage

For a fuzz target to be useful, it must have good coverage in the code that it
is testing. You can view the coverage for your fuzz targets by looking at the
[fuzzer stats]({{ site.baseurl }}/further-reading/clusterfuzz#fuzzer-stats)
dashboard on ClusterFuzz, as well as [coverage reports]({{ site.baseurl
}}/further-reading/clusterfuzz#coverage-reports).

To generate an aggregated code coverage report for your project, please see the
[code coverage]({{ site.baseurl }}/advanced-topics/code-coverage) page.

Coverage can often be improved by adding dictionaries, more inputs for seed
corpora, and fixing timeouts/out-of-memory bugs in your targets.

## Regression Testing

Fuzz targets should be regularly tested (not necessarily fuzzed!) as a part of
the project's regression testing process. One way to do so is to link the fuzz
target with a simple standalone driver
([example](https://github.com/llvm-mirror/compiler-rt/tree/master/lib/fuzzer/standalone))
that runs the provided inputs, then use this driver with the seed corpus created
in previous step. We recommend you use
[sanitizers](https://github.com/google/sanitizers) during regression testing.

Examples: [SQLite](https://www.sqlite.org/src/artifact/d9f1a6f43e7bab45),
[openssl](https://github.com/openssl/openssl/blob/master/fuzz/test-corpus.c).

## Performance

Fuzz targets should perform well, because high memory usage and/or slow
execution speed can slow the down the growth of coverage and finding of new
bugs. ClusterFuzz provides a [performance analyzer]({{ site.baseurl
}}/further-reading/clusterfuzz/#performance-analyzer) for each fuzz target that
shows problems that are impacting performance.

## Not a project member?

If you are a member of the project you want to fuzz, most of the steps above are
simple. However in some cases, someone outside the project team may want to fuzz
the code, and the project maintainers are not interested in helping.

In such cases, we can host the fuzz targets, dictionaries, etc. in OSS-Fuzz's 
repository and mention them in the Dockerfile. It's not ideal, because the fuzz
targets will not be continuously tested, so may quickly bitrot.

Examples: [libxml2](https://github.com/google/oss-fuzz/tree/master/projects/libxml2),
[c-ares](https://github.com/google/oss-fuzz/tree/master/projects/c-ares), [expat](https://github.com/google/oss-fuzz/tree/master/projects/expat).

If you are not a project maintainer, we may not be able to CC you to security
bugs found by OSS-Fuzz.
