# Reproducing OSS-Fuzz issues

You've been CC'ed on an OSS-Fuzz issue
([examples](https://bugs.chromium.org/p/oss-fuzz/issues/list?can=1&q=Type%3ABug%2CBug-Security)), now what?
Before attempting to fix the bug, you should be able to reliably reproduce it. 

Every issue has a [reproducer](glossary.md#reproducer) (aka "testcase") file attached.
Download it. If the issue is not public, you will need to login using your
[Google account](https://support.google.com/accounts/answer/176347?hl=en)
([why?](faq.md#why-we-require-an-e-mail-associated-with-a-google-account))
that the bug report CCs.
This file contains the bytes that were fed to the [Fuzz Target](http://libfuzzer.info/#fuzz-target).

If you have already [integrated](ideal_integration.md) the fuzz target with your build and test system, 
all you do is run:
<pre>
./fuzz_target_binary <testcase_path>
</pre>

If this is a timeout bug, add the <b><i>-timeout=25</i></b> argument.
If this is a OOM bug, add the <b><i>-rss_limit_mb=2048</i></b> argument.
Read more on how timeouts and OOMs are handed [here](faq.md#how-do-you-handle-timeouts-and-ooms).

Depending on the nature of the bug, the fuzz target binary needs to be built with the appropriate [sanitizer](https://github.com/google/sanitizers)
(e.g. if this is a buffer overflow, with [AddressSanitizer](http://clang.llvm.org/docs/AddressSanitizer.html)).

If you are not sure how to build the fuzzer using the project's build system,
you may also use Docker ([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)) commands 
to replicate the exact build steps used by OSS-Fuzz and then feed the reproducer input to the fuzz target.

- *Reproduce using latest OSS-Fuzz build:* 

   <pre>
python infra/helper.py reproduce $PROJECT_NAME <fuzzer_name> <testcase_path>
   </pre>

  It builds the fuzzer from the most recent successful OSS-Fuzz build (usually last night's sources)
  and feeds the testcase file to the target function. 
  
  E.g. for [libxml2](../projects/libxml2) project with fuzzer named `libxml2_xml_read_memory_fuzzer`, it will be: 
  
   <pre>
python infra/helper.py reproduce libxml2 libxml2_xml_read_memory_fuzzer ~/Downloads/testcase
   </pre>
- *Reproduce using local source checkout:*

    <pre>
python infra/helper.py build_fuzzers $PROJECT_NAME <source_path>
python infra/helper.py reproduce $PROJECT_NAME <fuzzer_name> <testcase_path>
    </pre>
  
  This is essentially the previous command that additionally mounts local sources into the running container.
- *Fix issue*. Write a patch to fix the issue in your local checkout and then use the previous command to verify the fix (i.e. no crash occurred). 
   [Use gdb](debugging.md#debugging-fuzzers-with-gdb) if needed.
- *Submit fix*. Submit the fix in the project's repository. ClusterFuzz will automatically pick up the changes, recheck the testcase and will close the issue (in &lt; 1 day).
- *Improve fuzzing support*. Consider [improving fuzzing support](ideal_integration.md) in your project's build and test system.
