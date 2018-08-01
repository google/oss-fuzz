## Debugging Build Scripts

While developing your build script, it may be useful to run bash within the
container:

```bash
$ python infra/helper.py shell $PROJECT_NAME  # runs /bin/bash within container
$ compile                                     # run compilation manually
```

## Debugging Fuzzers with GDB

If you wish to debug a fuzz target with gdb, you may use the base-runner-debug
image:

```bash
# Copy input testcase into host output directory so that it can be accessed
# within the Docker image.
$ cp /path/to/testcase build/out/$PROJECT_NAME

# Run Docker image containing GDB.
$ python infra/helper.py shell base-runner-debug
$ gdb --args /out/$PROJECT_NAME/$FUZZ_TARGET_NAME /out/$PROJECT_NAME/testcase
```

Note that the base-runner-debug image does not have access to your sources, so
you will not be able to do source code level debugging. We recommend integrating
your fuzz target upstream as part of [ideal integration](ideal_integration.md)
for debugging purposes.
