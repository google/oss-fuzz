# this script was added by Vlad

PROJECT_NAME=libpng
FUZZING_TARGET=libpng_read_fuzzer

# * build the target fuzzzer with coverage instrumentation this time
python3 infra/helper.py build_fuzzers --sanitizer coverage $PROJECT_NAME

# * now visulaise coverage of the seeds in the build/out/corpus directory
python3 infra/helper.py coverage $PROJECT_NAME --no-serve --fuzz-target=$FUZZING_TARGET --corpus-dir=build/out/corpus
