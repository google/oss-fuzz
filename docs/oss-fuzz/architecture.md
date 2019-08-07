---
layout: default
title: Architecture
permalink: /architecture/
nav_order: 1
parent: OSS-Fuzz
---

# Architecture
![diagram]({{ site.baseurl }}/images/process.png?raw=true)

The following process is used for projects in OSS-Fuzz:

- A maintainer of an opensource project or an outside volunteer creates
one or more [fuzz targets](http://libfuzzer.info/#fuzz-target)
and [integrates]({{ site.baseurl }}/advanced-topics/ideal-integration/) them
with the project's build and test system.
- The project is [accepted to OSS-Fuzz]({{ site.baseurl }}/getting-started/accepting-new-projects/).
- When [ClusterFuzz]({{ site.baseurl }}/furthur-reading/clusterfuzz) finds a
  bug, an issue is automatically reported in the OSS-Fuzz
  [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) 
  ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9)).
  ([Why use a different tracker?]({{ site.baseurl }}/faq/#why-do-you-use-a-different-issue-tracker-for-reporting-bugs-in-oss-projects)).
  Project owners are CC-ed to the bug report.
- The project developer fixes the bug upstream and credits OSS-Fuzz for the
  discovery (commit message should contain the string **'Credit to OSS-Fuzz'**).
- [ClusterFuzz]({{ site.baseurl }}/furthur-reading/clusterfuzz) automatically
  verifies the fix, adds a comment and closes the issue
  ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=53#c3)).
- 30 days after the fix is verified or 90 days after reporting (whichever is
  earlier), the issue becomes *public*
  ([guidelines]({{ site.baseurl }}/getting-started/bug-disclosure-guidelines/)).

