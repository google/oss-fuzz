---
layout: default
title: FAQ
nav_order: 7
permalink: /faq/
---

# Frequently Asked Questions

- TOC
{:toc}
---

## Where can I learn more about fuzzing?

We recommend reading [libFuzzer tutorial] and the other docs in [google/fuzzing]
repository. These and some other resources are listed on the
[useful links]({{ site.baseurl }}/reference/useful-links/#tutorials) page.

[google/fuzzing]: https://github.com/google/fuzzing/tree/master/docs
[libFuzzer tutorial]: https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md

## What kind of projects are you accepting?

We accept established projects that have a critical impact on infrastructure and
user security. We will consider each request on a case-by-case basis, but some
things we keep in mind are:

  - Exposure to remote attacks (e.g. libraries that are used to process
    untrusted input).
  - Number of users/other projects depending on this project.

We hope to relax this requirement in the future though, so keep an eye out even
if we are not able to accept your project at this time!

## How can I find potential fuzz targets in my open source project?

You should look for places in your code that:

  - consume un-trusted data from users or from the network.
  - consume complex input data even if it's 'trusted'.
  - use an algorithm that has two or more implementations
    (to verify their equivalence).
  - look for existing fuzz target [examples](https://github.com/google/oss-fuzz/tree/master/projects)
    and find similarities.

## Where can I store fuzz target sources and the build script if it's not yet accepted upstream?

Fuzz target sources as well as the build script may temporarily live inside the
`projects/<your_project>` directory in the OSS-Fuzz repository. Note that we do
not accept integrations that rely on forked repositories. Refer to the
[ideal integration guide] for the preferred long term solution.

## My project is not open source. Can I use OSS-Fuzz?

You cannot use OSS-Fuzz, but you can use [ClusterFuzz] which OSS-Fuzz is based
on. ClusterFuzz is an open-source fuzzing infrastructure that you can deploy in
your own environment and run continuously at scale.

OSS-Fuzz is a production instance of ClusterFuzz, plus the code living in
[OSS-Fuzz repository]: build scripts, `project.yaml` files with contacts, etc.

[OSS-Fuzz repository]: https://github.com/google/oss-fuzz

## Why do you use a [different issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) for reporting bugs in OSS projects?

Security access control is important for the kind of issues that OSS-Fuzz detects,
hence why by default issues are only opened on the OSS-Fuzz tracker.
You can opt-in to have them on Github as well by adding the `file_github_issue`
attribute to your `project.yaml` file. Note that this is only for visibility's
purpose, and that the actual details can be found by following the link to the
OSS-Fuzz tracker.

## Why do you require a Google account for authentication?

Our [ClusterFuzz]({{ site.baseurl }}/further-reading/clusterfuzz) fuzzing
infrastructure and [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list)
require a Google account for authentication. Note that an alternate email
address associated with a Google account does not work due to appengine api
limitations.

## Why do you use Docker?

Building fuzzers requires building your project with a fresh Clang compiler and
special compiler flags.  An easy-to-use Docker image is provided to simplify
toolchain distribution. This also simplifies our support for a variety of Linux
distributions and provides a reproducible environment for fuzzer
building and execution.

## How do you handle timeouts and OOMs?

If a single input to a [fuzz target]({{ site.baseurl }}/reference/glossary/#fuzz-target)
requires more than **~25 seconds** or more than **2.5GB RAM** to process, we
report this as a timeout or an OOM (out-of-memory) bug
(examples: [timeouts](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=%22Crash+Type%3A+Timeout%22),
[OOMs](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q="Crash+Type%3A+Out-of-memory")).
This may or may not be considered as a real bug by the project owners,
but nevertheless we treat all timeouts and OOMs as bugs
since they significantly reduce the efficiency of fuzzing.

Remember that fuzzing is executed with AddressSanitizer or other
sanitizers which introduces a certain overhead in RAM and CPU.

We currently do not have a good way to deduplicate timeout or OOM bugs.
So, we report only one timeout and only one OOM bug per fuzz target.
Once that bug is fixed, we will file another one, and so on.

Currently we do not offer ways to change the memory and time limits.

## Can I launch an additional process (e.g. a daemon) from my fuzz target?

No. In order to get all the benefits of in-process, coverage-guided fuzz testing,
it is required to run everything inside a single process. Any child processes
created outside the main process introduces heavy launch overhead and is not
monitored for code coverage.

Another rule of thumb is: "the smaller fuzz target is, the better it is". It is
expected that your project will have many fuzz targets to test different
components, instead of a single fuzz target trying to cover everything.
Think of fuzz target as a unit test, though it is much more powerful since it
helps to test millions of data permutations rather than just one.

## What if my fuzz target finds a bug in another project (dependency) ?

Every bug report has a crash stack-trace that shows where the crash happened.
Using that, you can debug the root cause and see which category the bug falls in:

- If this is a bug is due to an incorrect usage of the dependent project's API
in your project, then you need to fix your usage to call the API correctly.
- If this is a real bug in the dependent project, then you should CC the
maintainers of that project on the bug. Once CCed, they will get automatic
access to all the information necessary to reproduce the issue. If this project
is maintained in OSS-Fuzz, you can search for contacts in the respective
project.yaml file.

## What if my fuzzer does not find anything?

If your fuzz target is running for many days and does not find bugs or new
coverage, it may mean several things:
- We've covered all reachable code. In order to cover more code we need more
  fuzz targets.
- The [seed corpus]({{ site.baseurl }}/getting-started/new-project-guide#seed-corpus) is not good enough and the
  fuzzing engine(s) are not able to go deeper based on the existing seeds.
  Need to add more seeds.
- There is some crypto/crc stuff in the code that will prevent any fuzzing
  engine from going deeper, in which case the crypto should be disabled in
  [fuzzing mode](http://libfuzzer.info#fuzzer-friendly-build-mode).
  Examples: [openssl](https://github.com/openssl/openssl/tree/master/fuzz#reproducing-issues),
  [boringssl](https://boringssl.googlesource.com/boringssl/+/HEAD/FUZZING.md#Fuzzer-mode)
- It is also possible that the fuzzer is running too slow
  (you may check the speed of your targets at https://oss-fuzz.com/)

In either case, look at the
[coverage reports]({{ site.baseurl }}/further-reading/clusterfuzz#coverage-reports)
for your target(s) and figure out why some parts of the code are not covered.

## What if my fuzzer does not find new coverage or bugs after a while?

It is common for fuzzers to plateau and stop finding new coverage or bugs.
[Fuzz Introspector](https://github.com/ossf/fuzz-introspector) helps you
evaluate your fuzzers' performance.
It can help you identify bottlenecks causing your fuzzers to plateau.
It provides aggregated and individual fuzzer reachability and coverage reports.
Developers can either introduce a new fuzz target or modify an existing one to
reach previously unreachable code.
Here are
[case studies](https://github.com/ossf/fuzz-introspector/blob/main/doc/CaseStudies.md)
where Fuzz Introspector helped developers improve fuzzing of a project.
Fuzz Introspector reports are available on the [OSS-Fuzz homepage](https://oss-fuzz.com/)
or through this [index](http://oss-fuzz-introspector.storage.googleapis.com/index.html).

Developers can also use Fuzz Introspector on their local machines.
Detailed instructions are available
[here](https://github.com/ossf/fuzz-introspector/tree/main/oss_fuzz_integration#build-fuzz-introspector-with-oss-fuzz).

## Why are code coverage reports public?

We work with open source projects and try to keep as much information public as
possible. We believe that public code coverage reports do not put users at risk,
as they do not indicate the presence of bugs or lack thereof.

## Why is the coverage command complaining about format compatibility issues?

This may happen if the Docker images fetched locally become out of sync. Make
sure you run the following command to pull the most recent images:

```bash
$ python infra/helper.py pull_images
```

Please refer to
[code coverage]({{ site.baseurl }}/advanced-topics/code-coverage/) for detailed
information on code coverage generation.

## What happens when I rename a fuzz target ?

If you rename your fuzz targets, the existing bugs for those targets will get
closed and fuzzing will start from scratch from a fresh corpora
(seed corpus only). Similar corpora will get accumulated over time depending on
the number of cpu cycles that original fuzz target has run. If this is not
desirable, make sure to copy the accumulated corpora from the original fuzz
target (instructions to download
[here]({{ site.baseurl }}/advanced-topics/corpora/#downloading-the-corpus)) and
restore it to the new GCS location later (instruction to find the
new location [here]({{ site.baseurl }}/advanced-topics/corpora/#viewing-the-corpus-for-a-fuzz-target)).

## Does OSS-Fuzz support AFL or honggfuzz or Centipede?

OSS-Fuzz *uses* the following
[fuzzing engines]({{ site.baseurl }}/reference/glossary/#fuzzing-engine):

1. [libFuzzer](https://llvm.org/docs/LibFuzzer.html).
1. [AFL++](https://github.com/AFLplusplus/AFLplusplus), an improved and
   well-maintained version of [AFL](https://lcamtuf.coredump.cx/afl/).
1. [Honggfuzz](https://github.com/google/honggfuzz).
1. [Centipede (Experimental)](https://github.com/google/centipede).

Follow the [new project guide] and OSS-Fuzz will use all its fuzzing engines
on your code.

## What are the specs on your machines?

OSS-Fuzz builders have 32CPU/28.8GB RAM.

Fuzzing machines only have a single core and fuzz targets should not use more
than 2.5GB of RAM.

## Are there any restrictions on using test cases / corpora generated by OSS-Fuzz?

No, you can freely use (i.e. share, add to your repo, etc.) the test cases and
corpora generated by OSS-Fuzz. OSS-Fuzz infrastructure is fully open source
(including [ClusterFuzz], various fuzzing engines, and other dependencies). We
have no intent to restrict the use of the artifacts produced by OSS-Fuzz.

[ClusterFuzz]: https://github.com/google/clusterfuzz
[new project guide]: {{ site.baseurl }}/getting-started/new-project-guide/
[ideal integration guide]: {{ site.baseurl }}/getting-started/new-project-guide/
