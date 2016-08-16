Building all infra images:

```bash
# run from project root
docker build -t ossfuzz/base infra/base-images/base && \
docker build -t ossfuzz/base-clang infra/base-images/base-clang && \
docker build -t ossfuzz/base-libfuzzer infra/base-images/base-libfuzzer && \
docker build -t ossfuzz/libfuzzer-runner infra/base-images/libfuzzer-runner
```
