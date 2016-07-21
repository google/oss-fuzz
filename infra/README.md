Infrastructure
==============

This directory contains infrastructure definition for oss-fuzz project:

* `base-images` - docker images for building fuzzers & corresponding jenkins
  pipeline.
* `docker-cleanup` - jenkins pipeline to clean stale docker images & processes.
* `jenkins-cluster` - kubernetes cluster definition for our jenkins-based build.
