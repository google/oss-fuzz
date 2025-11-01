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

We support the [libFuzzer], [AFL++], [Honggfuzz], and [Centipede] fuzzing engines in
combination with [Sanitizers], as well as [ClusterFuzz], a distributed fuzzer
execution environment and reporting tool.

[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
[AFL++]: https://github.com/AFLplusplus/AFLplusplus
[Honggfuzz]: https://github.com/google/honggfuzz
[Centipede]: https://github.com/google/centipede
[Sanitizers]: https://github.com/google/sanitizers
[ClusterFuzz]: https://github.com/google/clusterfuzz
[ClusterFuzzLite]: https://google.github.io/clusterfuzzlite/

Currently, OSS-Fuzz supports C/C++, Rust, Go, Python and Java/JVM code. Other
languages supported by [LLVM] may work too. OSS-Fuzz supports fuzzing x86_64
and i386 builds.

[LLVM]: https://llvm.org


## Project history
OSS-Fuzz was launched in 2016 in response to the
[Heartbleed] vulnerability, discovered in [OpenSSL], one of the
most popular open source projects for encrypting web traffic. The vulnerability
had the potential to affect almost every internet user, yet was caused by a
relatively simple memory buffer overflow bug that could have been detected by
fuzzing—that is, by running the code on randomized inputs to intentionally cause
unexpected behaviors or crashes. At the time, though, fuzzing
was not widely used and was cumbersome for developers, requiring extensive
manual effort.

Google created OSS-Fuzz to fill this gap: it's a free service that runs fuzzers
for open source projects and privately alerts developers to the bugs detected.
Since its launch, OSS-Fuzz has become a critical service for the open source
community, growing beyond C/C++ to
detect problems in memory-safe languages such as Go, Rust, and Python.

[Heartbleed]: https://heartbleed.com/ 
[OpenSSL]: https://www.openssl.org/

## Learn more about fuzzing

This documentation describes how to use OSS-Fuzz service for your open source
project. To learn more about fuzzing in general, we recommend reading [libFuzzer
tutorial] and the other docs in [google/fuzzing] repository. These and some
other resources are listed on the [useful links] page.

[google/fuzzing]: https://github.com/google/fuzzing/tree/master/docs
[libFuzzer tutorial]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md
[useful links]: {{ site.baseurl }}/reference/useful-links/#tutorials

## Trophies
As of August 2023, OSS-Fuzz has helped identify and fix over [10,000] vulnerabilities and [36,000] bugs across [1,000] projects.

[10,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=Type%3DBug-Security%20label%3Aclusterfuzz%20-status%3ADuplicate%2CWontFix&can=1
[36,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=Type%3DBug%20label%3Aclusterfuzz%20-status%3ADuplicate%2CWontFix&can=1
[1,000]: https://github.com/google/oss-fuzz/tree/master/projects
