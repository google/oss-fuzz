---
layout: default
title: Architecture
permalink: /architecture/
nav_order: 1
parent: OSS-Fuzz
---

# Architecture
![OSS-Fuzz architecture diagram]({{ site.baseurl }}/images/process.png?raw=true)

The process works like this:

1. A maintainer of an open source project (or an outside volunteer) creates
one or more [fuzz targets](http://libfuzzer.info/#fuzz-target)
and [integrates]({{ site.baseurl }}/advanced-topics/ideal-integration/) them
with the project's build and test system.
1. The project is [accepted to OSS-Fuzz]({{ site.baseurl }}/getting-started/accepting-new-projects/) and the developer commits their build configurations.
1. The OSS-Fuzz [builder](https://github.com/google/oss-fuzz/tree/master/infra/build) builds the project from the committed configs.
1. The builder uploads the fuzz targets to the OSS-Fuzz GCS bucket.
1. [ClusterFuzz]({{ site.baseurl }}/further-reading/clusterfuzz) downloads the fuzz targets and begins to fuzz the projects.
1. When Clusterfuzz finds a
  bug, it reports the issue automatically to the OSS-Fuzz
  [issue tracker](https://bugs.chromium.org/p/oss-fuzz/issues/list) 
  ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=9)).
  ([Why use a different tracker?]({{ site.baseurl }}/faq/#why-do-you-use-a-different-issue-tracker-for-reporting-bugs-in-oss-projects))
1. Project owners are CCed on the bug report.
1. The project developer fixes the bug upstream and credits OSS-Fuzz for the
  discovery (the commit message should contain the string **'Credit to OSS-Fuzz'**).

Once the developer fixes the bug, [ClusterFuzz]({{ site.baseurl }}/further-reading/clusterfuzz) automatically
verifies the fix, adds a comment, and closes the issue ([example](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=53#c3)). After the fix is verified or 90 days after reporting (whichever is earlier), the issue becomes [public]({{ site.baseurl }}/getting-started/bug-disclosure-guidelines/).

