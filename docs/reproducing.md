# Reproducing OSS-Fuzz issues

You've been CC'ed on an OSS-Fuzz issue, now what? Before attempting a fix you should be able to reliably reproduce an issue. 

The process is much simpler if you have Docker installed ([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)), but 
is entirely possible to do without.

## Bug tracker reports

Bug reports in our bug tracker have the format:

```
Detailed report: <link to ClusterFuzz report>

Target: target
Fuzzer: libFuzzer_target_fuzzer
Fuzzer binary: fuzzer
Job Type: libFuzzer_asan_libchewing

Crash Type: Heap-use-after-free
Crash Address: 0x1337
Crash State
  Frame1
  Frame2
  Frame3

Regressed: <Regression range link>

Minimized Testcase (size): <Testcase download link>
```

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

## Manual

Manual process is fully documented on main [libFuzzer page](http://llvm.org/docs/LibFuzzer.html).
To manully reproduce the issue you have to:
- fetch the toolchain: http://llvm.org/docs/LibFuzzer.html#versions
- build the target with toolchain and sanitizer: http://llvm.org/docs/LibFuzzer.html#building
- build the fuzzer from target-related code in [targets/](../targets/)
- run the fuzzer on downloaded testcase
- develop a fix and submit it upstream

ClusterFuzz will automatically pick up the changes, recheck the testcase and will close the issue.

