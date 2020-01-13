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

## Learn more about fuzzing

This documentation describes how to use OSS-Fuzz service for your open source project.
To learn more about fuzzing in general, we recommend reading [libFuzzer tutorial]
and the other docs in [google/fuzzing] repository. These and some other resources
are listed on the [useful links]({{ site.baseurl }}/reference/useful-links/#tutorials) page.

[google/fuzzing]: https://github.com/google/fuzzing/tree/master/docs
[libFuzzer tutorial]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md

## Trophies
As of January 2020, OSS-Fuzz has found over [16,000] bugs in [250] open source projects.

[16,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=-status%3AWontFix%2CDuplicate%20-component%3AInfra&can=1
[250]: https://github.com/google/oss-fuzz/tree/master/projects
