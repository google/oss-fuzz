# Reproducing oss-fuzz issues

You've been CC'ed on an oss-fuzz issue, now what? Before attempting a fix you should be able to reliably reproduce an issue. 


The process is much simpler if you have Docker installed ([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)), but 
is entirely possible to do without.

## Docker

If you have docker installed, follow these steps:

- *Download testcase.* Each issue has a minimized testcase link. Download the testcase to a file.
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
- *Fix the issue.* Use the previous command to verify you fixed the issue locally. Consult the
  [debugging](debugging.md) document for your debugging needs.
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

