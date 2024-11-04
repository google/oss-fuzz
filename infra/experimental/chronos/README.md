# Usage
Under `OSS-Fuzz` root directory:
```bash
export PROJECT=libiec61850
export FUZZ_TARGET=fuzz_mms_decode.c
export FUZZING_LANGUAGE=c

infra/experimental/chronos/prepare-recompile "$PROJECT" "$FUZZ_TARGET" "$FUZZING_LANGUAGE"
python infra/helper.py build_image "$PROJECT"
# AddressSanitizer.
docker run -ti --entrypoint="/bin/sh" --env SANITIZER="address" --name "${PROJECT}-origin-asan" "gcr.io/oss-fuzz/${PROJECT}" -c "compile && rm -rf /out/*"
docker commit --change 'CMD ["compile"] --change 'ENTRYPOINT /bin/sh' "${PROJECT}-origin-asan" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached-asan"
docker run -ti --entrypoint="recompile" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached-asan"

# Coverage measurement.
docker run -ti --entrypoint="/bin/sh" --env SANITIZER="coverage" --name "${PROJECT}-origin-cov" "gcr.io/oss-fuzz/${PROJECT}" -c "compile && rm -rf /out/*"
docker commit --change 'CMD ["compile"] --change 'ENTRYPOINT /bin/sh' "${PROJECT}-origin-cov" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached-cov"
docker run -ti --entrypoint="recompile" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached-cov"
```

# Assumptions
1. Fuzzer: Chronos assumes `libFuzzer`. Other fuzzers are not well-supported, but may work by setting ENV `FUZZING_ENGINE` in project's `Dockerfile`.
2. Sanitizer: Chronos assumes `AddressSanitizer`. Other sanitizers may work by adding setting ENV `SANITIZER` in project's `Dockerfile`.
