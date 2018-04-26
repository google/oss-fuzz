# Frequently Asked Questions

## What kind of projects are you accepting?

We are currently in a beta status, and still working out issues in our service. At this point, we
can only commit to supporting established projects that have a critical impact on infrastructure and
user security. We will consider each request on a case-by-case basis, but some things we keep in mind are:

  - Exposure to remote attacks (e.g. libraries that are used to process untrusted input).
  - Number of users/other projects depending on this project.

We hope to relax this requirement in the future though, so keep an eye out even if we are not able
to accept your project at this time!

## How can I find potential fuzz targets in my open source project?

You should look for places in your code that:

  - consume un-trusted data from users or from the network.
  - consume complex data input or event if it's 'trusted'.
  - use an algorithm that has two or more implementations (to verify their equivalence).
  - look for existing fuzz target [examples](https://github.com/google/oss-fuzz/tree/master/projects) and find similarities.

## Why do you use a [different issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) for reporting bugs in OSS projects?

Security access control is important for the kind of issues that OSS-Fuzz detects.
We will reconsider the Github issue tracker once the
[access control feature](https://github.com/isaacs/github/issues/37) is available.

## Why do you require a Google account for authentication?

Our [ClusterFuzz](clusterfuzz.md) fuzzing infrastructure and [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) require a Google account for authentication. Note that an alternate email address associated with a Google acount does not work due to appengine api limitations.

## Why do you use Docker?

Building fuzzers requires building your project with a fresh Clang compiler and special compiler flags. 
An easy-to-use Docker image is provided to simplify toolchain distribution. This also simplifies our
support for a variety of Linux distributions and provides a reproducible and secure environment for fuzzer
building and execution.

## How do you handle timeouts and OOMs?

If a single input to a [fuzz target](glossary.md#fuzz-target)
requires more than **~25 seconds** or more than **2GB RAM** to process, we
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
it is required to run everything inside a single process. Any child processes created
outside the main process introduces heavy launch overhead and is not monitored for
code coverage.

Another rule of thumb is: "the smaller fuzz target is, the better it is". It is
expected that your project will have many fuzz targets to test different components,
instead of a single fuzz target trying to cover everything. Think of fuzz target
as a unit test, though it is much more powerful since it helps to test millions
of data permutations rather than just one.

## What if my fuzz target finds a bug in another project (dependency) ?

Every bug report has a crash stack-trace that shows where the crash happened.
Using that, you can debug the root cause and see which category the bug falls in:

- If this is a bug is due to an incorrect usage of the dependent project's API 
in your project, then you need to fix your usage to call the API correctly.
- If this is a real bug in the dependent project, then you should CC the maintainers
of that project on the bug. Once cced, they will get automatic access to all the
information necessary to reproduce the issue. If this project is maintained in OSS-Fuzz,
you can search for contacts in the respective project.yaml file.

## What if my fuzzer does not find anything? 

If your fuzz target is running for many days and does not find bugs or new coverage, it may mean several things: 
- We've covered all reachable code. In order to cover more code we need more fuzz targets.
- The [seed corpus](new_project_guide.md#seed-corpus) is not good enough and the fuzzing engine(s) are not able to go deeper based on the existing seeds. Need to add more seeds. 
- There is some crypto/crc stuff in the code that will prevent any fuzzing engine from going deeper, in which case the crypto should be disabled in [fuzzing mode](http://libfuzzer.info#fuzzer-friendly-build-mode). Examples: [openssl](https://github.com/openssl/openssl/tree/master/fuzz#reproducing-issues), [boringssl](https://boringssl.googlesource.com/boringssl/+/HEAD/FUZZING.md#Fuzzer-mode)
- It is also possible that the fuzzer is running too slow (you may check the speed of your targets at https://oss-fuzz.com/)

In either case, look at the [coverage reports](clusterfuzz.md#coverage-reports) for your target(s) and figure out why some parts of the code are not covered. 

## What happens when I rename a fuzz target ?
If you rename your fuzz targets, the existing bugs for those targets will get closed and fuzzing will start from scratch from a fresh corpora (seed corpus only). Similar corpora will get accumulated over time depending on the number of cpu cycles that original fuzz target has run. If this is not desirable, make sure to copy the accumulated corpora from the original fuzz target (instructions to download [here](corpora.md#downloading-the-corpus)) and restore it to the new GCS location later (instruction to find the new location [here](corpora.md#viewing-the-corpus-for-a-fuzz-target)).

## Does OSS-Fuzz support AFL?
OSS-Fuzz *uses* [AFL](http://lcamtuf.coredump.cx/afl/) as one of its [fuzzing engines](glossary.md#fuzzing-engine) but this is an implementation detail. Just follow the [ideal integration guide](ideal_integration.md) and OSS-Fuzz will use all its fuzzing engines on your code.

## Does OSS-Fuzz support Honggfuzz?
Analogically to [AFL](#does-oss-fuzz-support-afl).
