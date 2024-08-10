# Usage
Under `OSS-Fuzz` root directory:
```bash
export PROJECT=libiec61850
export FUZZ_TARGET=fuzz_mms_decode.c
export FUZZING_LANGUAGE=c
infra/experimental/chronos/prepare-recompile "$PROJECT" "$FUZZ_TARGET" "$FUZZING_LANGUAGE"
python infra/helper.py build_image "$PROJECT"
docker run -ti --entrypoint="/bin/sh" --name "${PROJECT}-origin" "gcr.io/oss-fuzz/${PROJECT}" -c "compile && rm /out/*"
docker commit "${PROJECT}-origin" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached"
docker run -ti --entrypoint="recompile" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached"
```

# Assumptions
1. Fuzzer: Chronos assumes `libFuzzer`. Other fuzzers are not well-supported, but may work by setting ENV `FUZZING_ENGINE` in project's `Dockerfile`.
2. Sanitizer: Chronos assumes `AddressSanitizer`. Other sanitizers may work by adding setting ENV `SANITIZER` in project's `Dockerfile`.
