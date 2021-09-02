#include <stddef.h>
#include <stdint.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>
#include <unistd.h>

#include "rar.hpp"

namespace fs = std::__fs::filesystem;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // unrar likes to create files in the current directory.
  // So, the following few lines created and 'cd' to a directory named 'o'
  // in the current working directory.
  std::error_code code, ok;
  fs::path original_path = fs::current_path(code);
  if (code != ok) return 0;

  fs::path out_path = original_path / "o";
  bool created = fs::create_directory(out_path, code);
  if (code != ok) return 0;

  fs::current_path(out_path, code);
  if (code != ok) return 0;

  static const std::string filename = "temp.rar";
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

  // 'cd' back to the original directory and delete 'o' along with
  // all its contents.
  fs::current_path(original_path, code);
  if (code != ok) return 0;
  fs::remove_all(out_path, code);
  if (code != ok) return 0;
  return 0;
}
