# OSS-Fuzz - Continuous Fuzzing for Open Source Software

## Introduction

[Fuzz testing](https://en.wikipedia.org/wiki/Fuzz_testing) is a well-known
technique for uncovering various kinds of programming errors in software.
Many of these detectable errors (e.g. [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow)) can have serious security implications.

We successfully deployed
[guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)
and found [hundreds](https://bugs.chromium.org/p/chromium/issues/list?can=1&q=label%3AStability-LibFuzzer+-status%3ADuplicate%2CWontFix) of security vulnerabilities and stability bugs. We now want to share the experience and the service with the open source community. 

In cooperation with the [Core Infrastructure Initiative](https://www.coreinfrastructure.org/), 
OSS-Fuzz aims to make common open source software more secure and stable by
combining modern fuzzing techniques and scalable
distributed execution.

We support [libFuzzer](http://llvm.org/docs/LibFuzzer.html) and [AFL](http://lcamtuf.coredump.cx/afl/) as fuzzing engines
in combination with [Sanitizers](https://github.com/google/sanitizers).
[ClusterFuzz](https://google.github.io/oss-fuzz/furthur-reading/clusterfuzz)
provides a distributed fuzzer execution environment and reporting. You can
checkout ClusterFuzz [here](https://github.com/google/clusterfuzz).

Currently OSS-Fuzz supports C and C++ code (other languages supported by [LLVM](http://llvm.org) may work too).

## Documentation
You can find detailed documentation [here](https://google.github.io/oss-fuzz).

## Trophies
As of August 2019, OSS-Fuzz has found [~14,000] bugs in over [200] open source
projects.

[~14,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=-status%3AWontFix%2CDuplicate+-Infra
[200]: https://github.com/google/oss-fuzz/tree/master/projects

## Blog posts

* 2016-12-01 ([1](https://opensource.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html),
[2](https://testing.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html),
[3](https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html))
* 2017-05-08 ([1](https://opensource.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html),
[2](https://testing.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html),
[3](https://security.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html))
* 2018-11-06 ([1](https://security.googleblog.com/2018/11/a-new-chapter-for-oss-fuzz.html))


