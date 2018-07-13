## Debugging Build Scripts

While developing your build script, it may be useful to run bash within the
container:

```bash
$ python infra/helper.py shell $PROJECT_NAME  # runs /bin/bash within container
$ compile                                     # run compilation manually
```

## Debugging Fuzzers with GDB

If you decide to debug a fuzzer with gdb (which is already installed in
base-runner-debug image), you may run the following:

```bash
$ python infra/helper.py shell base-runner-debug
$ gdb /out/$PROJECT_NAME/$FUZZ_TARGET_NAME
```

Note that the base-runner-debug image does not have access to your sources, so
you will not be able to do source code level debugging. We recommend integrating
your fuzz target upstream as part of (ideal integration)[ideal_integration.md]
for debugging purposes.
