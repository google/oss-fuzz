---
layout: default
title: Reproducing
parent: Advanced topics
nav_order: 5
permalink: /advanced-topics/reproducing
---

# Reproducing OSS-Fuzz issues

You've been CC'ed on an OSS-Fuzz issue
([examples](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=Type%3ABug%2CBug-Security)),
now what? Before attempting to fix the bug, you should be able to reliably
reproduce it. 

- TOC
{:toc}
---

## Fuzz target bugs
Every issue has a [reproducer]({{ site.baseurl }}/reference/glossary/#reproducer)
(aka "testcase") file attached.
Download it. If the issue is not public, you will need to login using your
[Google account](https://support.google.com/accounts/answer/176347?hl=en)
([why?]({{ site.baseurl }}/faq/#why-do-you-require-a-google-account-for-authentication))
that the bug report CCs.
This file contains the bytes that were fed to the [fuzz target](http://libfuzzer.info/#fuzz-target).

If you have already
[integrated]({{ site.baseurl }}/advanced-topics/ideal-integration/)
the fuzz target with your build and test system, all you do is run:
```bash
$ ./fuzz_target_binary <testcase_path>
```

If this is a timeout bug, add the **-timeout=25** argument.
If this is an OOM bug, add the **-rss_limit_mb=2048** argument.
Read more on how timeouts and OOMs are handed
[here]({{ site.baseurl }}/faq/#how-do-you-handle-timeouts-and-ooms).

Depending on the nature of the bug, the fuzz target binary needs to be built
with the appropriate [sanitizer](https://github.com/google/sanitizers)
(e.g. if this is a buffer overflow, with
[AddressSanitizer](http://clang.llvm.org/docs/AddressSanitizer.html)).

If you are not sure how to build the fuzzer using the project's build system,
you may also use Docker
([how?]({{ site.baseurl }}/getting-started/new-project-guide/#prerequisites),
[why?]({{ site.baseurl }}/faq/#why-do-you-use-docker)) commands 
to replicate the exact build steps used by OSS-Fuzz and then feed the reproducer
input to the fuzz target.

## Building using Docker

### Pull the latest Docker images

```bash
$ python infra/helper.py pull_images
```

  Docker images get regularly updated with a newer version of build tools, build
  configurations, scripts, and other changes. In some cases, a particular issue
  can be reproduced only with a fresh image being used.

### Build the image and the fuzzers

```bash
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> \
    --architecture <x86_64/i386> $PROJECT_NAME
```

The `architecture` argument is only necessary if you want to specify `i386` configuration.

## Reproducing bugs
```bash
$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
```
  
Find the type of sanitizer used in the report using the value in the
**Sanitizer** column. It is one of the following:
  * **address** for AddressSanitizer
  * **memory** for MemorySanitizer
  * **undefined** for UndefinedBehaviorSanitizer

E.g. for building [libxml2](https://github.com/google/oss-fuzz/tree/master/projects/libxml2)
project with UndefinedBehaviorSanitizer (undefined) instrumentation and
reproduce a crash testcase for a fuzzer named `libxml2_xml_read_memory_fuzzer`,
it will be: 

```bash
$ python infra/helper.py build_image libxml2
$ python infra/helper.py build_fuzzers --sanitizer undefined libxml2
$ python infra/helper.py reproduce libxml2 libxml2_xml_read_memory_fuzzer ~/Downloads/testcase
```

## Reproduce using local source checkout

```bash
$ python infra/helper.py build_fuzzers \
    --sanitizer <address/memory/undefined> $PROJECT_NAME <source_path>
$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
```

This is essentially the previous command that additionally mounts local sources
into the running container.

- *Fix issue*. Write a patch to fix the issue in your local checkout and then
   use the previous command to verify the fix (i.e. no crash occurred). 
   [Use gdb]({{ site.baseurl }}/advanced-topics/debugging/#debugging-fuzzers-with-gdb)
   if needed.
- *Submit fix*. Submit the fix in the project's repository. ClusterFuzz will
  automatically pick up the changes, recheck the testcase and will close the
  issue (in &lt; 1 day).
- *Improve fuzzing support*. Consider
   [improving fuzzing support]({{ site.baseurl }}/advanced-topics/ideal-integration/)
   in your project's build and test system.

## Reproducing build failures
Our infrastructure runs some sanity tests to make sure that your build was
correctly configured, even if it succeeded. To reproduce these locally, run:

```bash
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> \
    --engine <libfuzzer/afl/honggfuzz> --architecture <x86_64/i386> $PROJECT_NAME
$ python infra/helper.py check_build  --sanitizer <address/memory/undefined> \
    --engine <libfuzzer/afl/honggfuzz> --architecture <x86_64/i386> $PROJECT_NAME \
    <fuzz_target_name>
```

Note that unless you have a reason to think the build is an `i386` build, the build
is probably an `x86_64` build and the `architecture` argument can be omitted.

For reproducing a `coverage` build failure, follow
[Code Coverage page]({{ site.baseurl }}/advanced-topics/code-coverage) to build
your project and generate a code coverage report.
