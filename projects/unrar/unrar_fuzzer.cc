#include <memory>
#include <stddef.h>
#include <string>
#include <unistd.h>

#include "rar.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  char filename[] = "mytemp.XXXXXX";
  int fd = mkstemp(filename);
  write(fd, data, size);

  std::unique_ptr<CommandData> cmd_data(new CommandData);
  cmd_data->ParseArg(const_cast<wchar_t *>(L"-p"));
  cmd_data->ParseArg(const_cast<wchar_t *>(L"x"));
  cmd_data->ParseDone();
  std::wstring wide_filename(filename, filename + strlen(filename));
  cmd_data->AddArcName(wide_filename.c_str());

  try {
    CmdExtract extractor(cmd_data.get());
    extractor.DoExtract();
  } catch (...) {
  }

  close(fd);
  unlink(filename);

  return 0;
}
