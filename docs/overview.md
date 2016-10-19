# Overview

* what we are doing
  - how to add the library
    * create a pull request and provide the following information in 
      description:
      - project website & details
      - SRC repository location
      - oss-fuzz related contact persons
  - which libraries do we accept
    * libraries with significant user base
    * libraries critical to global IT infrastructure & business
  - how we file bugs
    * we file a bug in https://bugs.chromium.org/p/oss-fuzz/issues/list
    * we will perform initial triage
    * CC contact person(s) to the bug
  - who we assign
    * we ask for contact person(s) when you sign up
  - who can add the library to oss-fuzz
    * active members of the library development community
  - how we disclose bugs
    * at first bugs are seen only by people added to a bug
    * bug is made public:
      - after bug is fixed
      - after 90 days since reported to developers
  - integration with own bug tracker
    * we are considering integration with GitHub issues, but at
    this moment it lacks security capabilities for responsible
    bug disclosure
  - mailing list? (do we need any?)
    * keep in touch - watch the project?
  - how do bug reports look like
    * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=53
  - how to contact us
    * file an issue in GitHub tracker


* why we are doing
  - fuzzing
    * one of the best way to find certain kinds of problems
    * many discovered problems have real security implications
    * why fuzz?
  - chrome experience
  - continuous fuzzing

* internals/design
  - build system
  - ClusterFuzz
    - what is it? - distributed continuous fuzzing system
    - links
    - maybe not that prominent

