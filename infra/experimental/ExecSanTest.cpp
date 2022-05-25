#include <stdlib.h>
#include <string>
#include <iostream>
// int main() {
//   return system("echo hi");
// }


extern "C" int LLVMFuzzerTestOneInput(char* data, size_t size) {
  std::string str(data, size);
  std::cout << "INPUT" << str << std::endl;
  system(str.c_str());
  return 0;
}
