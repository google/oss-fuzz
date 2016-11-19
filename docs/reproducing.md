# Reproducing OSS-Fuzz issues

You've been CC'ed on an OSS-Fuzz issue
([examples](https://bugs.chromium.org/p/oss-fuzz/issues/list)), now what?
Before attempting a fix the bug you should be able to reliably reproduce it. 

Every issue has a reproducer file attached.
Download it. If the issue is not public, you will need to login using your Google account
that is CC-ed to the bug report.
This file contains the bytes that were fed to the [Fuzz Target](http://libfuzzer.info/#fuzz-target).

If you have [properly integrated](ideal_integration.md) the fuzz target with your build and test system
all you is to run
```
./fuzz_target_binary REPRODUCER_FILE
```
Depending on the nature of the bug, the fuzz target binary needs to be built with the appropriate sanitizer
(e.g. if this is a buffer overflow, with [AddressSanitizer](http://clang.llvm.org/docs/AddressSanitizer.html)).

**TODO**

Another option is to use the Docker commands (**TODO: link**) to replicate the exact build steps
used by OSS-Fuzz and then feed the reproducer input to the target.

## **TODO careate separate file with all docker commands**
([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)), but 
is entirely possible to do without.


Click the testcase download link to download the testcase (you may need to
login, using the same Google account that you've been CC'ed with). The "Detailed
report" link provides the full stack trace, as well as some additional details
that may be useful.

For the following instructions, `$target` is the text after `Target: ` in the
report, and `$fuzzer` is the text after `Fuzzer binary: `. `$testcase_file` is
the path to the testcase you just downloaded.

Note that for older reports, `Fuzzer binary:` and `Target:` may not exist. In
this case, please extract this information from the `Fuzzer:` field. This is
usually in the format `libFuzzer_$target_$fuzzer`.

## Docker

If you have docker installed, follow these steps:

- *Reproduce from nightly sources:* 

   <pre>
docker run --rm -v <b><i>$testcase_file</i></b>:/testcase -t ossfuzz/<b><i>$target</i></b> reproduce <b><i>$fuzzer</i></b>
   </pre>

  It builds the fuzzer from nightly sources (in the image) and runs it with testcase input.
  E.g. for libxml2 it will be: 
  
   <pre>
docker run --rm -ti -v <b><i>~/Downloads/testcase</i></b>:/testcase ossfuzz/<b><i>libxml2</i></b> reproduce <b><i>libxml2_xml_read_memory_fuzzer</i></b>
   </pre>
- *Reproduce from local sources:*

    <pre>
docker run --rm  -v <b><i>$target_checkout_dir</i></b>:/src/<b><i>$target</i></b> \
                     -v <b><i>$reproducer_file</i></b>:/testcase -t ossfuzz/<b><i>$target</i></b> reproduce <b><i>$fuzzer</i></b>
    </pre>
  
  This is essentially the previous command that additonally mounts local sources into the running container.
- *Fix the issue.* Use the previous command to verify you fixed the issue locally. 
   [Use gdb](debugging.md#debugging-fuzzers-with-gdb) if needed.
- *Submit the fix.* ClusterFuzz will automatically pick up the changes, recheck the testcase 
  and will close the issue.
