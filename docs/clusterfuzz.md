# ClusterFuzz

ClusterFuzz is the distributed fuzzing infrastructure behind OSS-Fuzz. It was initially built
for fuzzing Chrome at scale.

## Web interface

ClusterFuzz also provides [web interface](https://clusterfuzz-external.appspot.com/v2)
to view statistics about your fuzzer targets, as well as current crashes.

Note that access is restricted to library developers that we auto CC on new bug
reports.

## Fuzzer stats

You can view statistics about your fuzzers (e.g. speed, coverage information,
memory usage) on our fuzzer statistics dashboard.

![stats]
(https://raw.githubusercontent.com/google/oss-fuzz/master/docs/freetype_stats.png)

## Coverage reports

We also provide coverage reports, where we highlight the parts of source code that are being
reached by your fuzzer.

![coverage_1]
(https://raw.githubusercontent.com/google/oss-fuzz/master/docs/freetype_coverage_1.png)

![coverage_2]
(https://raw.githubusercontent.com/google/oss-fuzz/master/docs/freetype_coverage_2.png)

## Testcase reports

ClusterFuzz will automatically de-duplicate and file reproducible crashes into
our [bug tracker](https://bugs.chromium.org/p/monorail). We provide a crash
report page that gives you the stack trace, a link to the crashing testcase, and
regression ranges where the bug was most likely introduced.

![report]
(https://raw.githubusercontent.com/google/oss-fuzz/master/docs/pcre2_testcase.png)

