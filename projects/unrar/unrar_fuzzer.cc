#include <fstream>
#include <memory>
#include <sstream>
#include <unistd.h>

#include "rar.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::stringstream ss;
  ss << "temp-" << getpid() << ".rar";
  static const std::string filename = ss.str();
  std::ofstream file(filename,
                     std::ios::binary | std::ios::out | std::ios::trunc);
  if (!file.is_open()) {
    return 0;
  }
  file.write(reinterpret_cast<const char *>(data), size);
  file.close();

  std::unique_ptr<CommandData> cmd_data(new CommandData);
  cmd_data->ParseArg(const_cast<wchar_t *>(L"-p"));
  cmd_data->ParseArg(const_cast<wchar_t *>(L"x"));
  cmd_data->ParseDone();
  std::wstring wide_filename(filename.begin(), filename.end());
  cmd_data->AddArcName(wide_filename.c_str());

  try {
    CmdExtract extractor(cmd_data.get());
    extractor.DoExtract();
  } catch (...) {
  }

  unlink(filename.c_str());

  return 0;
}
