cp /untitled/index_in_sandbox.sh /index_in_sandbox.sh
cp /untitled/clang_wrapper.py /clang
cp /untitled/clang_wrapper.py /clang++
chmod ugo+x /index_in_sandbox.sh
export SANITIZER="none"
export FUZZING_ENGINE="none"
export LIB_FUZZING_ENGINE="/usr/lib/libFuzzingEngine.a"
export FUZZING_LANGUAGE="c++"
export CFLAGS="$CFLAGS -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -O0 -glldb -fsanitize=address -Wno-invalid-offsetof -fsanitize-coverage=bb,no-prune,trace-pc-guard -gen-cdb-fragment-path /out/cdb -Qunused-arguments -lc++abi"
export CXX="/clang++"
export CC="/clang"
/clang++ -c -Wall -Wextra -pedantic -std=c++20 -glldb -O0 /untitled/fuzzing_engine.cc -o /out/untitled_fuzzing_engine.o -gen-cdb-fragment-path /out/cdb -Qunused-arguments
ar rcs /untitled/fuzzing_engine.a /out/untitled_fuzzing_engine.o
ln -s /untitled/fuzzing_engine.a /usr/lib/libFuzzingEngine.a
/usr/local/bin/compile

# docker pull gcr.io/oss-fuzz-base/base-builder
# infra/helper.py build_image skcms
# # docker pull gcr.io/oss-fuzz/skcms

# Running the actual build:
# rm -f /usr/lib/libFuzzingEngine.a && docker run -it -v path/to/oss-fuzz/untitled:/untitled:rw  gcr.io/oss-fuzz/skcms /bin/bash
# bash /untitled/untitled_script.sh 
