# Usage
Under `OSS-Fuzz` root directory:
```bash
export PROJECT=libiec61850
export FUZZ_TARGET=fuzz_mms_decode.c
export FUZZING_LANGUAGE=c
infra/experimental/chronos/prepare-recompile "$PROJECT" "$FUZZ_TARGET" "$FUZZING_LANGUAGE"
python infra/helper.py build_image "$PROJECT"
docker run -ti --entrypoint="compile" --name "${PROJECT}-origin" "gcr.io/oss-fuzz/${PROJECT}"
docker commit "${PROJECT}-origin" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached"
docker run -ti --entrypoint="recompile" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached" 
```
