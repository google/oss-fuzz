
  clang++ -std=c++11 -I. -I/usr/include \
  -Ilibpng -Llibpng \
  -fsanitize=address -fsanitize-coverage=trace-pc-guard \
  libpng_read_fuzzer.cc libFuzzer.a libpng/.libs/libpng16.a -lz
  ./a.out -runs=5 -max_len=16000
