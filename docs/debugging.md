## Debugging Build Scripts

While developing your build script, it may be useful to run bash within the
container:

```bash
$ python infra/helper.py shell $PROJECT_NAME  # runs /bin/bash within container
$ compile                                     # run compilation manually
```

## Debugging Fuzzers with GDB

If you decide to debug a fuzzer with gdb (which is already installed in base-runner-debug image),
you will need to start a container in privileged mode:

```bash
docker run -ti --privileged -v /tmp/out:/out gcr.io/oss-fuzz-base/base-runner-debug gdb /out/<fuzz_target_name>
```
