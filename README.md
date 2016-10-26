# oss-fuzz - Continuous Fuzzing for Open Source Software

> *Status*: Beta. We are preparing the project for the first public release. Documentation and smoothing the process is our main priority.

[FAQ](docs/faq.md)
| [New Target Guide](docs/new_target.md) 
| [Targets List](targets/README.md)


[Create New Issue](https://github.com/google/oss-fuzz/issues/new) for questions or feedback.

## Goals

Oss-fuzz aims to make common open source software more secure by
combining modern white-box fuzzing techniques together with scalable
distributed execution.

At the first stage of the project we plan to combine
[libFuzzer](http://llvm.org/docs/LibFuzzer.html) with various `clang`
[sanitizers](https://github.com/google/sanitizers).
[ClusterFuzz](https://blog.chromium.org/2012/04/fuzzing-for-security.html)
provides distributed fuzzer execution environment and reporting.

## Background

[Fuzz testing](https://en.wikipedia.org/wiki/Fuzz_testing) is a well-known
technique for uncovering certain types of programming errors in software.
Many detectable errors (e.g. buffer overruns) have real security
implications.

Our previous experience applying [libFuzzer](http://llvm.org/docs/LibFuzzer.html)
to do [guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)
has proved very successful.


## Process Overview

The following process is used for targets in oss-fuzz:

- a target is accepted to oss-fuzz.
- oss-fuzz build server build target fuzzers  regularly and submits them to
  ClusterFuzz for execution.
- ClusterFuzz continuously executes target fuzzers
- when fuzzing uncovers an issue, ClusterFuzz creates an internal testcase.
- issues are automatically triaged and filed in the oss-fuzz [testcase issue
  tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list). 
  [Example issue](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9).
  ([Why different tracker?](docs/faq.md#why-do-you-use-a-different-issue-tracker-for-reportig-bugs-in-fuzz-targets))
- if the target project has a defined process for reporting security issues,
  we will follow it, otherwise we will cc target engineers on an issue.
- engineers fix the issue and land the fix upstream.
- fuzzing infrastructure automatically verifies the fix, adds a comment and
  closes the issue.
- after the issue is fixed or after 90 days since reporting has passed, the issue
  becomes *public*.

The following table summarizes issue visibility through the process:

| Issue State    | Visibility |
|----------|------------|
| New      | oss-fuzz engineers |
| Reported | oss-fuzz engineers + everyone CC'ed on the bug |
| Fixed & Verified | public |
| Lapsed (90 days since report) | public |

## Accepting New Targets

In order to be accepted to oss-fuzz, an open-source project must 
have a significant user base and/or be critical to the global IT infrastructure.

To submit a new target to oss-fuzz:
- create a pull request with a change to [targets/README.md](targets/README.md) providing the following information:
  * project site and details
  * source code repository location
  * a link to the project security issue reporting process *OR*
  * an e-mail of the engineering contact person to be CCed on issue. This
    has to be an e-mail with google account that belongs to an 
    established project committer (according to VCS logs).
    If this is not you or address differs from VCS, an informal e-mail verification will be required.
    This e-mail will also be publicly listed in our [Targets](targets/README.md)
    page.
- once accepted by an oss-fuzz project member, follow the [New Target Guide](docs/new_target.md)
  to write the code.


## Bug Disclosure Guidelines

Following Google's standard [disclosure policy](https://googleprojectzero.blogspot.com/2015/02/feedback-and-data-driven-updates-to.html)
oss-fuzz will adhere to following disclosure principles:
  - **90-day deadline**. After notifying target authors, we will open reported
    issues in 90 days, or sooner if the fix is released.
  - **Weekends and holidays**. If a deadline is due to expire on a weekend or
    US public holiday, the deadline will be moved to the next normal work day.
  - **Grace period**. We will have a 14-day grace period. If a 90-day deadline
    will expire but upstream engineers let us know before the deadline that a
    patch is scheduled for release on a specific day within 14 days following
    the deadline, the public disclosure will be delayed until the availability
    of the patch.

## Documentation

* [New Target Guide](docs/new_target.md) walks through steps necessary to add new targets to oss-fuzz.
* [Running and Building Fuzzers](docs/building_running_fuzzers.md) documents the process for fuzzers that are
  *part of target project* source code repository.
* [Running and Building External Fuzzers](docs/building_running_fuzzers_external.md) documents the process for fuzzers that are
  *part of oss-fuzz* source code repository.
* [Targets List](targets/README.md) lists OSS targets added to oss-fuzz.
* [Chrome's Efficient Fuzzer Guide](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/+/HEAD/efficient_fuzzer.md) 
  while contains some chrome-specifics, is an excellent documentation on making your fuzzer better.

## Build status
[This page](https://oss-fuzz-build-logs.storage.googleapis.com/status.html)
gives the latest build logs for each target.

## Trophies

[This page](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=status%3AFixed%2CVerified+Type%3ABug%2CBug-Security+-component%3AInfra+)
gives a list of publically viewable (fixed) bugs found by oss-fuzz.

## References
* [libFuzzer documentation](http://libfuzzer.info)
* [libFuzzer tutorial](http://tutorial.libfuzzer.info)
* [Chromium Fuzzing Page](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/)

