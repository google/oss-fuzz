#include <fstream>
int main() {
  std::ofstream bombfile("/tmp/bombfile");
  bombfile << "bomb!" << std::endl;
  bombfile.close();
  return 0;
}
