# OSS-Fuzz: Continuous Fuzzing for Open Source Software

[Fuzz testing](https://en.wikipedia.org/wiki/Fuzz_testing) is a well-known
technique for uncovering programming errors in software.
Many of these detectable errors, like [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow), can have serious security implications. Google found [hundreds](https://bugs.chromium.org/p/chromium/issues/list?can=1&q=label%3AStability-LibFuzzer+-status%3ADuplicate%2CWontFix) of security vulnerabilities and stability bugs by deploying
[guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)
and, and we now want to share that service with the open source community. 

In cooperation with the [Core Infrastructure Initiative](https://www.coreinfrastructure.org/), 
OSS-Fuzz aims to make common open source software more secure and stable by
combining modern fuzzing techniques with scalable,
distributed execution.

We support the [libFuzzer](http://llvm.org/docs/LibFuzzer.html) and [AFL](http://lcamtuf.coredump.cx/afl/) fuzzing engines
in combination with [Sanitizers](https://github.com/google/sanitizers), as well as
[ClusterFuzz](https://github.com/google/clusterfuzz),
a distributed fuzzer execution environment and reporting tool. 

Currently, OSS-Fuzz supports C and C++ code, though other languages supported by [LLVM](http://llvm.org) may work too.

## Overview
![OSS-Fuzz process diagram](docs/images/process.png)

## Documentation
Read our [detailed documentation](https://google.github.io/oss-fuzz) to learn how to use OSS-Fuzz.

## Trophies
As of August 2019, OSS-Fuzz has found [~14,000] bugs in over [200] open source
projects.

[~14,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=-status%3AWontFix%2CDuplicate+-Infra
[200]: https://github.com/google/oss-fuzz/tree/master/projects

## Blog posts

* 2016-12-01 ([Open Source](https://opensource.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html),
[Testing](https://testing.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html),
[Security](https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html))
* 2017-05-08 ([Open Source](https://opensource.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html),
[Testing](https://testing.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html),
[Security](https://security.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html))
* 2018-11-06 ([Security](https://security.googleblog.com/2018/11/a-new-chapter-for-oss-fuzz.html))


