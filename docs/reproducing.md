# Reproducing OSS-Fuzz issues

You've been CC'ed on an OSS-Fuzz issue
([examples](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=Type%3ABug%2CBug-Security)), now what?
Before attempting to fix the bug, you should be able to reliably reproduce it. 

Every issue has a [reproducer](glossary.md#reproducer) (aka "testcase") file attached.
Download it. If the issue is not public, you will need to login using your
[Google account](https://support.google.com/accounts/answer/176347?hl=en)
([why?](faq.md#why-do-you-require-a-google-account-for-authentication))
that the bug report CCs.
This file contains the bytes that were fed to the [Fuzz Target](http://libfuzzer.info/#fuzz-target).

If you have already [integrated](ideal_integration.md) the fuzz target with your build and test system, 
all you do is run:
```bash
$ ./fuzz_target_binary <testcase_path>
```

If this is a timeout bug, add the <b><i>-timeout=25</i></b> argument.<br />
If this is an OOM bug, add the <b><i>-rss_limit_mb=2048</i></b> argument.<br />
Read more on how timeouts and OOMs are handed [here](faq.md#how-do-you-handle-timeouts-and-ooms).

Depending on the nature of the bug, the fuzz target binary needs to be built with the appropriate [sanitizer](https://github.com/google/sanitizers)
(e.g. if this is a buffer overflow, with [AddressSanitizer](http://clang.llvm.org/docs/AddressSanitizer.html)).

If you are not sure how to build the fuzzer using the project's build system,
you may also use Docker ([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)) commands 
to replicate the exact build steps used by OSS-Fuzz and then feed the reproducer input to the fuzz target.

## Building using Docker

```bash
$ python infra/helper.py build_image $PROJECT_NAME
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> $PROJECT_NAME
```

## Reproducing build checks
Our infrastructure runs some sanity tests to make sure that your build was correctly configured. To reproduce these locally, run:

```bash
$ python infra/helper.py check_build --sanitizer <address/memory/undefined> $PROJECT_NAME $FUZZER_NAME
```

## Reproducing bugs
```bash
$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
```
  
  E.g. for building [libxml2](../projects/libxml2) project with UndefinedBehaviorSanitizer instrumentation 
  and reproduce a crash testcase for a fuzzer named `libxml2_xml_read_memory_fuzzer`, it will be: 

```bash
$ python infra/helper.py build_image libxml2
$ python infra/helper.py build_fuzzers --sanitizer undefined libxml2
$ python infra/helper.py reproduce libxml2 libxml2_xml_read_memory_fuzzer ~/Downloads/testcase
```

## Reproduce using local source checkout

```bash
$ python infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> $PROJECT_NAME <source_path>
$ python infra/helper.py reproduce $PROJECT_NAME <fuzz_target_name> <testcase_path>
```

  This is essentially the previous command that additionally mounts local sources into the running container.
- *Fix issue*. Write a patch to fix the issue in your local checkout and then use the previous command to verify the fix (i.e. no crash occurred). 
   [Use gdb](debugging.md#debugging-fuzzers-with-gdb) if needed.
- *Submit fix*. Submit the fix in the project's repository. ClusterFuzz will automatically pick up the changes, recheck the testcase and will close the issue (in &lt; 1 day).
- *Improve fuzzing support*. Consider [improving fuzzing support](ideal_integration.md) in your project's build and test system.
