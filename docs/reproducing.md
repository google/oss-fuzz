# Reproducing oss-fuzz issues

You've been CC'ed on an oss-fuzz issue, now what? Before attempting a fix you should be able to reliably reproduce an issue. 
It is much simpler if you have Docker installed ([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)), but 
is entirely possible to do without.

## Docker-based

Follow these steps:

- *Download testcase.* Each issue has a minimized testcase link. Download the testcase to a file.
- *Reproduce from nightly sources.* Run:

    ```bash
    docker run --rm -v <testcase_file>:/testcase -t ossfuzz/<target> reproduce <fuzzer>`
    ```

  It builds the fuzzer from nightly sources (in the image) and runs it with reproducer input.
- *Reproduce with local sources.* Run:

    ```bash
    docker run --rm  -v <local_sources>:/src/target_src -v <reproducer_file>:/testcase -t ossfuzz/<target> reproduce <fuzzer>
    ```
  
  It is essentialy the previous command that addionally mounts local sources into the running container.
- *Fix the issue.* Use the previous command to help you fix the issue. 
- *Submit the fix.* Clusterfuzz will automatically pick up the changes, recheck the testcast 
  and will close the issue.
