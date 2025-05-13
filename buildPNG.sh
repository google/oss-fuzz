# this script was added by Vlad

PROJECT_NAME=libpng
FUZZING_TARGET=libpng_read_fuzzer

# * build the docker image with libpng repo
python3 infra/helper.py build_image $PROJECT_NAME

# * build the libpng library (and the fuzzer) inside the docker image created above
# python3 infra/helper.py build_fuzzers --sanitizer <address/memory/undefined> $PROJECT_NAME
python3 infra/helper.py build_fuzzers $PROJECT_NAME
