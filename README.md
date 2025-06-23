# OSS-Fuzz: Continuous Fuzzing for Open Source Software

[Fuzz testing] is a well-known technique for uncovering programming errors in
software. Many of these detectable errors, like [buffer overflow], can have
serious security implications. Google has found [thousands] of security
vulnerabilities and stability bugs by deploying [guided in-process fuzzing of
Chrome components], and we now want to share that service with the open source
community.

[Fuzz testing]: https://en.wikipedia.org/wiki/Fuzz_testing
[buffer overflow]: https://en.wikipedia.org/wiki/Buffer_overflow
[thousands]: https://issues.chromium.org/issues?q=label:Stability-LibFuzzer%20-status:Duplicate,WontFix
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

Currently, OSS-Fuzz supports C/C++, Rust, Go, Python, Java/JVM, and JavaScript code. Other languages
supported by [LLVM] may work too. OSS-Fuzz supports fuzzing x86_64 and i386
builds.

[LLVM]: https://llvm.org

## Overview
![OSS-Fuzz process diagram](docs/images/process.png)

## Documentation
Read our [detailed documentation] to learn how to use OSS-Fuzz.

[detailed documentation]: https://google.github.io/oss-fuzz

## Trophies
As of May 2025, OSS-Fuzz has helped identify and fix over 13,000 vulnerabilities and 50,000 bugs across [1,000] projects.

[1,000]: https://github.com/google/oss-fuzz/tree/master/projects

## Blog posts
* 2024-11-20 - [Leveling Up Fuzzing: Finding more vulnerabilities with AI]
* 2023-08-16 - [AI-Powered Fuzzing: Breaking the Bug Hunting Barrier]
* 2023-02-01 - [Taking the next step: OSS-Fuzz in 2023]
* 2022-09-08 - [Fuzzing beyond memory corruption: Finding broader classes of vulnerabilities automatically]
* 2021-12-16 - [Improving OSS-Fuzz and Jazzer to catch Log4Shell]
* 2021-03-10 - [Fuzzing Java in OSS-Fuzz]
* 2020-12-07 - [Improving open source security during the Google summer internship program]
* 2020-10-09 - [Fuzzing internships for Open Source Software]
* 2018-11-06 - [A New Chapter for OSS-Fuzz]
* 2017-05-08 - [OSS-Fuzz: Five months later, and rewarding projects]
* 2016-12-01 - [Announcing OSS-Fuzz: Continuous fuzzing for open source software]

[Leveling Up Fuzzing: Finding more vulnerabilities with AI]: https://security.googleblog.com/2024/11/leveling-up-fuzzing-finding-more.html
[AI-Powered Fuzzing: Breaking the Bug Hunting Barrier]: https://security.googleblog.com/2023/08/ai-powered-fuzzing-breaking-bug-hunting.html
[Announcing OSS-Fuzz: Continuous fuzzing for open source software]: https://opensource.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html
[OSS-Fuzz: Five months later, and rewarding projects]: https://opensource.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html
[A New Chapter for OSS-Fuzz]: https://security.googleblog.com/2018/11/a-new-chapter-for-oss-fuzz.html
[Fuzzing internships for Open Source Software]: https://security.googleblog.com/2020/10/fuzzing-internships-for-open-source.html
[Improving open source security during the Google summer internship program]: https://security.googleblog.com/2020/12/improving-open-source-security-during.html
[Fuzzing Java in OSS-Fuzz]: https://security.googleblog.com/2021/03/fuzzing-java-in-oss-fuzz.html
[Improving OSS-Fuzz and Jazzer to catch Log4Shell]: https://security.googleblog.com/2021/12/improving-oss-fuzz-and-jazzer-to-catch.html
[Fuzzing beyond memory corruption: Finding broader classes of vulnerabilities automatically]: https://security.googleblog.com/2022/09/fuzzing-beyond-memory-corruption.html
[Taking the next step: OSS-Fuzz in 2023]: https://security.googleblog.com/2023/02/taking-next-step-oss-fuzz-in-2023.html
