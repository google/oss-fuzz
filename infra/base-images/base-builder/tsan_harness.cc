#include <filesystem>
#include <iostream>
#include <fstream>
#include <iterator>
#include <vector>
#include <algorithm>

extern "C" {
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
}

int main(int argc, char** argv) {
  for (const auto& path :
           std::filesystem::recursive_directory_iterator(argv[1])) {
    if (!path.is_regular_file())
      continue;
    // std::cout << path << std::endl;
    std::ifstream file(path.path().string(), std::ios::binary);
    std::vector<uint8_t> contents(std::istreambuf_iterator<char>(file), {});
    const uint8_t* buf = &contents[0];
    size_t size = contents.size();
    LLVMFuzzerTestOneInput(buf, size);
  }
  return 0;
}
