---
layout: default
title: ClusterFuzz
parent: Further reading
nav_order: 1
permalink: /further-reading/clusterfuzz/
---

# ClusterFuzz

[ClusterFuzz](https://github.com/google/clusterfuzz) is the distributed fuzzing
infrastructure behind OSS-Fuzz. It was initially built for fuzzing Chrome at
scale.

- TOC
{:toc}
---

## Web interface

ClusterFuzz provides a [web interface](https://oss-fuzz.com)
to view statistics about your fuzz targets, as well as current crashes.

*Note*: Access is restricted to project developers who we auto CC on new bug
reports.

## Testcase reports

ClusterFuzz will automatically de-duplicate and file reproducible crashes into
our [bug tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list). We provide
a crash report page that gives you the stack trace, a link to the crashing
testcase, and regression ranges where the bug was most likely introduced.

![report]({{ site.baseurl }}/images/pcre2_testcase.png?raw=true)

## Fuzzer stats

You can view statistics about your fuzz targets (e.g. speed, coverage
information, memory usage) on our fuzzer statistics dashboard.

![stats]({{ site.baseurl }}/images/freetype_stats_graphs.png?raw=true)

![stats]({{ site.baseurl }}/images/freetype_stats_table.png?raw=true)

## Coverage reports

We provide coverage reports, where we highlight the parts of source code that
are being reached by your fuzz target. Make sure to look at the uncovered code
marked in red and add appropriate fuzz targets to cover those use cases.

![coverage_1]({{ site.baseurl }}/images/freetype_coverage_1.png?raw=true)
![coverage_2]({{ site.baseurl }}/images/freetype_coverage_2.png?raw=true)

## Performance analyzer

You can view performance issues that your fuzz target is running into (e.g.
leaks, timeouts, etc) by clicking on `Performance` link on our fuzzer statistics
dashboard. Make sure to fix all cited issues, so as to keep your fuzz target
running efficiently and finding new bugs.

![performance_analyzer]({{ site.baseurl }}/images/expat_performance_analyzer.png?raw=true)

## Crash stats

You can view statistics of crashes over time on our crash statistics dashboard.

![crash_stats]({{ site.baseurl }}/images/crash_stats.png?raw=true)
