---
layout: default
title: OSS-Fuzz
permalink: /
nav_order: 1
has_children: true
has_toc: false
---

# OSS-Fuzz

[Fuzz testing](https://en.wikipedia.org/wiki/Fuzz_testing) is a well-known
technique for uncovering programming errors in software.
Many of these detectable errors, like [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow),
can have serious security implications. Google has found [thousands] of security vulnerabilities and
stability bugs by deploying
[guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html),
and we now want to share that service with the open source community.

[thousands]: https://bugs.chromium.org/p/chromium/issues/list?q=label%3AStability-LibFuzzer%2CStability-AFL%20-status%3ADuplicate%2CWontFix&can=1

In cooperation with the [Core Infrastructure Initiative](https://www.coreinfrastructure.org/), 
OSS-Fuzz aims to make common open source software more secure and stable by
combining modern fuzzing techniques with scalable,
distributed execution.

We support the [libFuzzer](http://llvm.org/docs/LibFuzzer.html) and [AFL](http://lcamtuf.coredump.cx/afl/) fuzzing engines
in combination with [Sanitizers](https://github.com/google/sanitizers), as well as
[ClusterFuzz](https://github.com/google/clusterfuzz),
a distributed fuzzer execution environment and reporting tool. 

Currently, OSS-Fuzz supports C/C++, Rust, and Go code. Other languages supported by [LLVM](http://llvm.org) may work too.
OSS-Fuzz supports fuzzing x86_64 and i386 builds.

## Trophies
As of August 2019, OSS-Fuzz has found over [14,000] bugs in [200] open source projects.

[14,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=-status%3AWontFix%2CDuplicate+-Infra
[200]: https://github.com/google/oss-fuzz/tree/master/projects
