# OSS-Fuzz - Continuous Fuzzing for Open Source Software

> *Status*: Beta. We are now accepting applications from widely-used open source projects.

[FAQ](docs/faq.md)
| [Ideal Fuzzing Integration](docs/ideal_integration.md)
| [New Project Guide](docs/new_project_guide.md)
| [Reproducing Bugs](docs/reproducing.md)
| [Projects](projects)
| [Projects Issue Tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list)
| [Glossary](docs/glossary.md)


[Create New Issue](https://github.com/google/oss-fuzz/issues/new) for questions or feedback about OSS-Fuzz.

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

At the first stage of the project we use
[libFuzzer](http://llvm.org/docs/LibFuzzer.html) with
[Sanitizers](https://github.com/google/sanitizers). More fuzzing engines will be added later.
[ClusterFuzz](docs/clusterfuzz.md)
provides a distributed fuzzer execution environment and reporting.

Currently OSS-Fuzz supports C and C++ code (other languages supported by [LLVM](http://llvm.org) may work too).

## Process Overview

![diagram](docs/images/process.png?raw=true)

The following process is used for projects in OSS-Fuzz:

- A maintainer of an opensource project or an outside volunteer creates
one or more [fuzz targets](http://libfuzzer.info/#fuzz-target) 
and [integrates](docs/ideal_integration.md) them with the project's build and test system.
- The project is [accepted to OSS-Fuzz](#accepting-new-projects).
- When [ClusterFuzz](docs/clusterfuzz.md) finds a bug, an issue is automatically
  reported in the OSS-Fuzz [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) 
  ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9)).
  ([Why use a different tracker?](docs/faq.md#why-do-you-use-a-different-issue-tracker-for-reporting-bugs-in-oss-projects)).
  Project owners are CC-ed to the bug report.
- The project developer fixes the bug upstream and credits OSS-Fuzz for the discovery (commit message should contain
  the string **'Credit to OSS-Fuzz'**).
- [ClusterFuzz](docs/clusterfuzz.md) automatically verifies the fix, adds a comment and closes the issue ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=53#c3)).
- 30 days after the fix is verified or 90 days after reporting (whichever is earlier), the issue becomes *public*
  ([guidelines](#bug-disclosure-guidelines)).

<!-- NOTE: this anchor is referenced by oss-fuzz blog post -->
## Accepting New Projects

To be accepted to OSS-Fuzz, an open-source project must 
have a significant user base and/or be critical to the global IT infrastructure.
To submit a new project:
- [Create a pull request](https://help.github.com/articles/creating-a-pull-request/) with new 
`projects/<project_name>/project.yaml` file ([example](projects/libarchive/project.yaml)) giving at least the following information:
  * project homepage.
  * e-mail of the engineering contact person to be CCed on new issues. It should:
      * belong to an established project committer (according to VCS logs). If this is not you or the email address differs from VCS, an informal e-mail verification will be required.
      * be associated with a Google account ([why?](docs/faq.md#why-do-you-require-a-google-account-for-authentication)). If you use an alternate email address [linked to a Google Account](https://support.google.com/accounts/answer/176347?hl=en), it will ONLY give you access to filed bugs in [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) and NOT to [ClusterFuzz](clusterfuzz.md) dashboard (due to appengine api limitations).
  * Note that `project_name` can only contain alphanumeric characters, underscores(_) or dashes(-).
- Once accepted by an OSS-Fuzz project member, follow the [New Project Guide](docs/new_project_guide.md)
  to configure your project.


## Bug Disclosure Guidelines

Following [Google's standard disclosure policy](https://googleprojectzero.blogspot.com/2015/02/feedback-and-data-driven-updates-to.html)
OSS-Fuzz will adhere to following disclosure principles:
  - **Deadline**. After notifying project authors, we will open reported
    issues to the public in 90 days, or 30 days after the fix is released 
    (whichever comes earlier).
  - **Weekends and holidays**. If a deadline is due to expire on a weekend,
    the deadline will be moved to the next normal work day.
  - **Grace period**. We have a 14-day grace period. If a 90-day deadline
    expires but the upstream engineers let us know before the deadline that a
    patch is scheduled for release on a specific day within 14 days following
    the deadline, the public disclosure will be delayed until the availability
    of the patch.

## More Documentation

* [Glossary](docs/glossary.md) describes the common terms used in OSS-Fuzz.
* [New Project Guide](docs/new_project_guide.md) walks through the steps necessary to add new projects to OSS-Fuzz.
* [Ideal Integration](docs/ideal_integration.md) describes the steps to integrate fuzz targets with your project.
* [Accessing corpora](docs/corpora.md) describes how to access the corpora we use for fuzzing.
* [Fuzzer execution environment](docs/fuzzer_environment.md) documents the
  environment under which your fuzzers will be run.
* [Projects](projects) lists OSS projects currently analyzed by OSS-Fuzz.
* [Chrome's Efficient Fuzzer Guide](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/+/HEAD/efficient_fuzzer.md) 
  while containing some Chrome-specific bits, is an excellent guide to making your fuzzer better.
* Blog posts: 
  * 2016-12-01 ([1](https://opensource.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html),
[2](https://testing.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html),
[3](https://security.googleblog.com/2016/12/announcing-oss-fuzz-continuous-fuzzing.html))
  * 2017-05-08 ([1](https://opensource.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html),
[2](https://testing.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html),
[3](https://security.googleblog.com/2017/05/oss-fuzz-five-months-later-and.html))

## Build Status
[This page](https://oss-fuzz-build-logs.storage.googleapis.com/index.html)
gives the latest build logs for each project.

## Trophies

[This page](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=status%3AFixed%2CVerified+Type%3ABug%2CBug-Security+-component%3AInfra+)
gives a list of publicly-viewable fixed bugs found by OSS-Fuzz.

## References
* [libFuzzer documentation](http://libfuzzer.info)
* [libFuzzer tutorial](http://tutorial.libfuzzer.info)
* [libFuzzer workshop](https://github.com/Dor1s/libfuzzer-workshop)
* [Chromium Fuzzing Page](https://chromium.googlesource.com/chromium/src/testing/libfuzzer/)
* [ClusterFuzz](https://blog.chromium.org/2012/04/fuzzing-for-security.html)

