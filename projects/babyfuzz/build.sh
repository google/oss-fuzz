$CC $CFLAGS $LIB_FUZZING_ENGINE baby_overflow.c fuzz_target.c -o $OUT/baby_fuzzer
