# this script was added by Vlad

PROJECT_NAME=libpng
FUZZING_TARGET=libpng_read_fuzzer

# ! make sure that the build script was called, so that the coverage sanitisation is gone

# * clear the corpus 
# sudo rm -rf build/out/corpus # this fails if the directory already exists
mkdir build/out/corpus

# * run the libpng docker image
python3 infra/helper.py run_fuzzer --corpus-dir=build/out/corpus $PROJECT_NAME $FUZZING_TARGET
