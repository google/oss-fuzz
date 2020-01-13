# OSS-Fuzz: Continuous Fuzzing for Open Source Software

[Fuzz testing](https://en.wikipedia.org/wiki/Fuzz_testing) is a well-known
technique for uncovering programming errors in software.
Many of these detectable errors, like [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow), can have serious security implications. Google has found [thousands] of security vulnerabilities and stability bugs by deploying [guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html),
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

## Overview
![OSS-Fuzz process diagram](docs/images/process.png)

## Documentation
Read our [detailed documentation](https://google.github.io/oss-fuzz) to learn how to use OSS-Fuzz.

## Trophies
As of January 2020, OSS-Fuzz has found over [16,000] bugs in [250] open source projects.

[16,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=-status%3AWontFix%2CDuplicate%20-component%3AInfra&can=1
[250]: https://github.com/google/oss-fuzz/tree/master/projects

## Blog posts

* 2016-12-01 - [Announcing OSS-Fuzz: Continuous fuzzing for open source software](https://opensource.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html)
* 2017-05-08 - [OSS-Fuzz: Five months later, and rewarding projects](https://opensource.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html)
* 2018-11-06 - [A New Chapter for OSS-Fuzz](https://security.googleblog.com/2018/11/a-new-chapter-for-oss-fuzz.html)


