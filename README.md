# OSS-Fuzz - continuous fuzzing of open source software

> *Status*: Beta. We are preparing the project for public release. We are polishing the documentation and the process.

[FAQ](docs/faq.md)
| [Ideal Fuzzing Integration](docs/ideal_integration.md)
| [New Target Guide](docs/new_target.md) 
| [Reproducing](docs/reproducing.md) 
| [All Targets](targets)
| [Targets issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list)


[Create New Issue](https://github.com/google/oss-fuzz/issues/new) for questions or feedback.

## Why OSS-Fuzz?

[Fuzz testing](https://en.wikipedia.org/wiki/Fuzz_testing) is a well-known
technique for uncovering various kinds of programming errors in software.
Many detectable errors (e.g. buffer overruns) have real security implications.

We successfully deployed 
[guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)
and now want to share the experience and the service with the openssource community. 

OSS-Fuzz aims to make common open source software more secure by
combining modern fuzzing techniques and scalable
distributed execution.

At the first stage of the project we use
[libFuzzer](http://llvm.org/docs/LibFuzzer.html) with
[Sanitizers](https://github.com/google/sanitizers). More fuzzing engines will be added later.
[ClusterFuzz](docs/clusterfuzz.md)
provides distributed fuzzer execution environment and reporting.

## Process Overview

The following process is used for targets in OSS-Fuzz:

- A maintainer of an opensource project or an outside volunteer creates
one or more [Fuzz Target](http://libfuzzer.info/#fuzz-target) 
and [integrates](docs/ideal_integration.md) it with the project's build and test system.
- These targets are [accepted to OSS-Fuzz](docs/new_target.md).
- When [ClusterFuzz](docs/clusterfuzz.md) finds a bug, an issue is automatically
  reported in the OSS-Fuzz [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) 
  ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9)).
  ([Why different tracker?](docs/faq.md#why-do-you-use-a-different-issue-tracker-for-reportig-bugs-in-fuzz-targets)).
  Project owners are CC-ed to the bug report.
- The bug is fixed upstream.
- [ClusterFuzz](docs/clusterfuzz.md) automatically verifies the fix, adds a comment and closes the issue.
- 7 days after the fix is verified or after 90 days after reporting, the issue becomes *public*
  ([exact guidelines](#bug-disclosure-guidelines)).


## Accepting New Targets

In order to be accepted to OSS-Fuzz, an open-source target must 
have a significant user base and/or be critical to the global IT infrastructure.

To submit a new target to OSS-Fuzz:
- create a pull request with a change to [targets/README.md](targets/README.md) providing the following information:
  * target home site and details
  * source code repository location
  * a link to target security issue reporting process *OR*
  * an e-mail of the engineering contact person to be CCed on issue. This
    has to be an e-mail 
    [linked to a Google Account](https://support.google.com/accounts/answer/176347?hl=en)
    that belongs to an 
    established target committer (according to VCS logs).
    If this is not you or address differs from VCS, an informal e-mail verification will be required.
    This e-mail will also be publicly listed in our [Targets](targets/README.md)
    page.
- once accepted by an OSS-Fuzz project member, follow the [New Target Guide](docs/new_target.md)
  to write the code.


## Bug Disclosure Guidelines

Following Google's standard [disclosure policy](https://googleprojectzero.blogspot.com/2015/02/feedback-and-data-driven-updates-to.html)
OSS-Fuzz will adhere to following disclosure principles:
  - **90-day deadline**. After notifying target authors, we will open reported
    issues in 90 days, or 7 days after the fix is released.
  - **Weekends and holidays**. If a deadline is due to expire on a weekend or
    US public holiday, the deadline will be moved to the next normal work day.
  - **Grace period**. We will have a 14-day grace period. If a 90-day deadline
    will expire but upstream engineers let us know before the deadline that a
    patch is scheduled for release on a specific day within 14 days following
    the deadline, the public disclosure will be delayed until the availability
    of the patch.

## More Documentation

* [New Target Guide](docs/new_target.md) walks through steps necessary to add new targets to OSS-Fuzz.
* [Ideal Integration](docs/ideal_integration.md) describes the ideal way to integrate fuzz targets with your project.
* [Running and Building Fuzzers](docs/building_running_fuzzers.md) documents the process for fuzzers that are
  *part of target* source code repository.
* [Running and Building External Fuzzers](docs/building_running_fuzzers_external.md) documents the process for fuzzers that are
  *part of OSS-Fuzz* source code repository.
* [Fuzzer execution environment](docs/fuzzer_environment.md) documents the
  environment under which your fuzzers will be run.
* [Targets List](targets/README.md) lists OSS targets added to OSS-Fuzz.
* [Chrome's Efficient Fuzzer Guide](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/+/HEAD/efficient_fuzzer.md) 
  while contains some chrome-specifics, is an excellent documentation on making your fuzzer better.

## Build status
[This page](https://oss-fuzz-build-logs.storage.googleapis.com/status.html)
gives the latest build logs for each target.

## Trophies

[This page](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=status%3AFixed%2CVerified+Type%3ABug%2CBug-Security+-component%3AInfra+)
gives a list of publically viewable (fixed) bugs found by OSS-Fuzz.

## References
* [libFuzzer documentation](http://libfuzzer.info)
* [libFuzzer tutorial](http://tutorial.libfuzzer.info)
* [Chromium Fuzzing Page](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/)

