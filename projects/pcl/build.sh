mkdir build && cd build
cmake \
  -DCMAKE_CXX_FLAGS="-Wall -Wextra -Og -g -Wno-cpp ${CXX_FLAGS_EXTRA} ${SANITIZERS}" \
  $@ \
  ..
