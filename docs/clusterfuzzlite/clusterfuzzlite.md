---
layout: default
title: ClusterFuzzLite
has_children: true
nav_order: 8
permalink: /clusterfuzzlite/
<!-- Hide for now by setting "published: false" -->
published: false
---

# ClusterFuzzLite
ClusterFuzzLite is a lightweight, easy-to-use, fuzzing infrastructure that is
based off [ClusterFuzz]. ClusterFuzzLite is designed to run on [continuous integration] (CI)
systems, which means it is easy to set up and provides a familiar interface for
users.
Currently CIFuzz fully supports [GitHub Actions]. However ClusterFuzzLite is
designed so that supporting new CI systems is trivial and core features can be
used on any CI system without any additional effort.

See [Overview] for a more detailed description of how ClusterFuzzLite works and
how you can use it.

[continous integration]: https://en.wikipedia.org/wiki/Continuous_integration
[fuzzing]: https://en.wikipedia.org/wiki/Fuzzing
[ClusterFuzz]: https://google.github.io/clusterfuzz/
[GitHub Actions]: https://docs.github.com/en/actions
[Overview]: {{ site.baseurl }}/clusterfuzzlite/overview/
