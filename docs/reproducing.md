# Reproducing oss-fuzz issues

You've been CC'ed on an oss-fuzz issue, now what? Before attempting a fix you should be able to reliably reproduce an issue. 
It is much simpler if you have Docker installed ([how?](installing_docker.md), [why?](faq.md#why-do-you-use-docker)), but 
is entirely possible to do without.

## Docker-based

Follow these steps:

- download reproducer file
- run `docker run -v <reproducer_file>:/testcase -t ossfuzz/<target> reproduce <fuzzer>`. 
  This will build a fuzzer (with recent target sources in the image) and will run it with reproducer input.
- `docker run -v <local_sources>:/src/target_src -v <reproducer_file>:/testcase -t ossfuzz/<target> reproduce <fuzzer>` will build
  fuzzer from your *local* target source. Use it to develop a fix and verify.
