---
layout: default
title: OSS-Fuzz
permalink: /
nav_order: 1
has_children: true
has_toc: false
---

# OSS-Fuzz

[Fuzz testing] is a well-known technique for uncovering programming errors in
software. Many of these detectable errors, like [buffer overflow], can have
serious security implications. Google has found [thousands] of security
vulnerabilities and stability bugs by deploying [guided in-process fuzzing of
Chrome components], and we now want to share that service with the open source
community.

[Fuzz testing]: https://en.wikipedia.org/wiki/Fuzz_testing
[buffer overflow]: https://en.wikipedia.org/wiki/Buffer_overflow
[thousands]: https://bugs.chromium.org/p/chromium/issues/list?q=label%3AStability-LibFuzzer%2CStability-AFL%20-status%3ADuplicate%2CWontFix&can=1
[guided in-process fuzzing of Chrome components]: https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html

In cooperation with the [Core Infrastructure Initiative] and the [OpenSSF],
OSS-Fuzz aims to make common open source software more secure and stable by
combining modern fuzzing techniques with scalable, distributed execution.
Projects that do not qualify for OSS-Fuzz (e.g. closed source) can run their own
instances of [ClusterFuzz] or [ClusterFuzzLite].

[Core Infrastructure Initiative]: https://www.coreinfrastructure.org/
[OpenSSF]: https://www.openssf.org/

We support the [libFuzzer], [AFL++], and [Honggfuzz] fuzzing engines in
combination with [Sanitizers], as well as [ClusterFuzz], a distributed fuzzer
execution environment and reporting tool.

[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[Honggfuzz]: https://github.com/google/honggfuzz
[Sanitizers]: https://github.com/google/sanitizers
[ClusterFuzz]: https://github.com/google/clusterfuzz
[ClusterFuzzLite]: https://google.github.io/clusterfuzzlite/

Currently, OSS-Fuzz supports C/C++, Rust, Go, Python and Java/JVM code. Other
languages supported by [LLVM] may work too. OSS-Fuzz supports fuzzing x86_64
and i386 builds.

[LLVM]: https://llvm.org

## Learn more about fuzzing

This documentation describes how to use OSS-Fuzz service for your open source
project. To learn more about fuzzing in general, we recommend reading [libFuzzer
tutorial] and the other docs in [google/fuzzing] repository. These and some
other resources are listed on the [useful links] page.

[google/fuzzing]: https://github.com/google/fuzzing/tree/master/docs
[libFuzzer tutorial]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md
[useful links]: {{ site.baseurl }}/reference/useful-links/#tutorials

## Trophies
As of June 2021, OSS-Fuzz has found over [30,000] bugs in [500] open source
projects.

[30,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=-status%3AWontFix%2CDuplicate%20-component%3AInfra&can=1
[500]: https://github.com/google/oss-fuzz/tree/master/projects

