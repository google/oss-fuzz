## Debugging Build Scripts

While developing your build script, it may be useful to run bash within the
container:

```bash
$ python scripts/helper.py shell $LIB_NAME  # runs /bin/bash within container
$ bash /src/oss-fuzz/$LIB_NAME/build.sh     # to run the build script manually
```

## Debugging Fuzzers

If you decide to debug a fuzzer with gdb (which is already installed in libfuzzer-runner image),
you will need to start a container in privileged mode:

```bash
docker run -ti --privileged -v /tmp/out:/out -t ossfuzz/libfuzzer-runner /out/some_fuzzer_name
```
