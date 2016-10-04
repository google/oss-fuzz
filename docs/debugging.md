# Debugging Problems

## Debugging Build Scripts

While developing your build script, it may be useful to run bash within the
container:

```bash
$ python scripts/helper.py shell $LIB_NAME  # runs /bin/bash within container
$ bash /src/oss-fuzz/$LIB_NAME/build.sh     # to run the build script manually
```

