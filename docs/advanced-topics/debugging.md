---
layout: default
title: Debugging
parent: Advanced topics
nav_order: 4
permalink: /advanced-topics/debugging/
---

# Debugging issues
{: .no_toc}

- TOC
{:toc}
---

## Debugging build scripts

While developing your build script, it may be useful to run bash within the
container:

```bash
$ python infra/helper.py shell $PROJECT_NAME  # runs /bin/bash within container
$ compile                                     # runs compilation manually
```

## Debugging fuzzers with GDB

If you wish to debug a fuzz target with gdb, you can use the base-runner-debug
image:

```bash
# Copy input testcase into host output directory so it can be accessed
# within the Docker image.
$ cp /path/to/testcase build/out/$PROJECT_NAME

# Run the Docker image containing GDB.
$ python infra/helper.py shell base-runner-debug
$ gdb --args /out/$PROJECT_NAME/$FUZZ_TARGET_NAME /out/$PROJECT_NAME/testcase
```

**Note:** The `base-runner-debug` image does not have access to your sources, so
you will not be able to do source code level debugging. We recommend integrating
your fuzz target upstream as part of
[ideal integration]({{ site.baseurl }}/advanced-topics/ideal-integration/)
for debugging purposes.
