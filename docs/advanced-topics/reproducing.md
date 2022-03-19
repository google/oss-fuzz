---
layout: default
title: Reproducing
parent: Advanced topics
nav_order: 5
permalink: /advanced-topics/reproducing/
---

# Reproducing OSS-Fuzz issues
{: .no_toc}

You've been CCed on an OSS-Fuzz issue
([examples](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=Type%3ABug%2CBug-Security)).
Now what? Before attempting to fix the bug, you should be able to reliably
reproduce it. 

- TOC
{:toc}
---

## Fuzz target bugs

Every issue has a [reproducer file]({{ site.baseurl
}}/reference/glossary/#reproducer) (also know as a "testcase" file) attached.
Download it. This file contains the bytes that were fed to the [fuzz
target](http://libfuzzer.info/#fuzz-target).

**Note:** If the issue is not public, you will need to login using a
[Google account](https://support.google.com/accounts/answer/176347?hl=en)
([why?]({{ site.baseurl
}}/faq/#why-do-you-require-a-google-account-for-authentication)) that the bug
report CCs.

If you have already
[integrated]({{ site.baseurl }}/advanced-topics/ideal-integration/)
the fuzz target with your build and test system, all you have to do is run this command:
```bash
$ ./fuzz_target_binary <testcase_path>
```

For timeout bugs, add the `-timeout=65` argument. For OOM bugs, add the
`-rss_limit_mb=2560` argument. Read more on [how timeouts and OOMs are
handled]({{ site.baseurl }}/faq/#how-do-you-handle-timeouts-and-ooms).

Depending on the nature of the bug, the fuzz target binary needs to be built
with the appropriate [sanitizer](https://github.com/google/sanitizers)
(for example, if it's a buffer overflow, build with
[AddressSanitizer](http://clang.llvm.org/docs/AddressSanitizer.html)).

If you're not sure how to build the fuzzer using the project's build system,
you can also use Docker commands to replicate the exact build steps used by
OSS-Fuzz, then feed the reproducer input to the fuzz target ([how?]({{
site.baseurl }}/getting-started/new-project-guide/#prerequisites), [why?]({{
site.baseurl }}/faq/#why-do-you-use-docker)).

## Building using Docker

### Cloning OSS-Fuzz

To use the following `infra/helper.py` commands, you need a checkout of OSS-Fuzz:

```bash
$ git clone --depth=1 https://github.com/google/oss-fuzz.git
$ cd oss-fuzz
```

### Pull the latest Docker images

Docker images get regularly updated with a newer version of build tools, build
configurations, scripts, and other changes. In some cases, a particular issue
can be reproduced only with a fresh image being used. Pull the latest images
by running the following command:

```bash
$ python infra/helper.py pull_images
```

### Build the image and the fuzzers

Run the following commands:

```bash
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> \
    --architecture <x86_64/i386> $PROJECT_NAME
```

The `sanitizer` used in the report is the value in the
**Sanitizer** column. It's one of the following:
  * **address** for AddressSanitizer.
  * **memory** for MemorySanitizer.
  * **undefined** for UndefinedBehaviorSanitizer.

**Notes**:
   * The `architecture` argument is only necessary if you want to specify
`i386` configuration.
   * Some bugs (specially ones related to pointer and integer overflows) are reproducible only in 32 bit mode or only in 64 bit mode.
If you can't reproduce a particular bug building for x86_64, try building for i386.

## Reproducing bugs

After you build an image and a fuzzer, you can reproduce a bug by running the following command:

```bash
$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
```

For example, to build the [libxml2](https://github.com/google/oss-fuzz/tree/master/projects/libxml2)
project with UndefinedBehaviorSanitizer (`undefined`) instrumentation and
reproduce a crash testcase for a fuzzer named `libxml2_xml_read_memory_fuzzer`,
you would run: 

```bash
$ python infra/helper.py build_image libxml2
$ python infra/helper.py build_fuzzers --sanitizer undefined libxml2
$ python infra/helper.py reproduce libxml2 libxml2_xml_read_memory_fuzzer ~/Downloads/testcase
```

## Reproduce using local source checkout

You can also mount local sources into the running container by using these commands:

```bash
$ python infra/helper.py build_fuzzers \
    --sanitizer <address/memory/undefined> $PROJECT_NAME <source_path>
$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
```

Once you reproduce the bug, you can do the following:

- **Fix issue:** Write a patch to fix the issue in your local checkout, then
   use the previous command to verify the fix (i.e. no crash occurred). 
   [Use gdb]({{ site.baseurl }}/advanced-topics/debugging/#debugging-fuzzers-with-gdb)
   if needed.
- **Submit fix:** Submit the fix in the project's repository. ClusterFuzz will
  automatically pick up the changes, recheck the testcase, and close the
  issue (in &lt; 1 day).
- **Improve fuzzing support:** Consider
   [improving your integration with OSS-Fuzz]({{ site.baseurl }}/advanced-topics/ideal-integration/).

## Reproducing build failures

Our infrastructure runs some sanity tests to make sure that your build was
correctly configured, even if it succeeded. To reproduce these locally, run these commands:

```bash
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> \
    --engine <libfuzzer/afl/honggfuzz> --architecture <x86_64/i386> $PROJECT_NAME
$ python infra/helper.py check_build  --sanitizer <address/memory/undefined> \
    --engine <libfuzzer/afl/honggfuzz> --architecture <x86_64/i386> $PROJECT_NAME \
    <fuzz_target_name>
```

**Note:** Unless you have a reason to think the build is an `i386` build, the build
is probably an `x86_64` build and the `architecture` argument can be omitted.

If you need to reproduce a `coverage` build failure, follow the
[Code Coverage page]({{ site.baseurl }}/advanced-topics/code-coverage) to build
your project and generate a code coverage report.
