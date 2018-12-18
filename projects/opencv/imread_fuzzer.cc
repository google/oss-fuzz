#include <cstddef>
#include <cstdint>
#include <unistd.h>

#include <opencv2/opencv.hpp>

namespace {

static char* fuzzer_get_tmpfile(const uint8_t* data, size_t size) {
  char* filename_buffer = strdup("/tmp/generate_temporary_file.XXXXXX");
  if (!filename_buffer) {
    perror("Failed to allocate file name buffer.");
    abort();
  }
  const int file_descriptor = mkstemp(filename_buffer);
  if (file_descriptor < 0) {
    perror("Failed to make temporary file.");
    abort();
  }
  FILE* file = fdopen(file_descriptor, "wb");
  if (!file) {
    perror("Failed to open file descriptor.");
    close(file_descriptor);
    abort();
  }
  const size_t bytes_written = fwrite(data, sizeof(uint8_t), size, file);
  if (bytes_written < size) {
    close(file_descriptor);
    fprintf(stderr, "Failed to write all bytes to file (%zu out of %zu)",
            bytes_written, size);
    abort();
  }
  fclose(file);
  return filename_buffer;
}

static void fuzzer_release_tmpfile(char* filename) {
  if (unlink(filename) != 0) {
    perror("WARNING: Failed to delete temporary file.");
  }
  free(filename);
}

class FuzzerTemporaryFile {
 public:
  FuzzerTemporaryFile(const uint8_t* data, size_t size)
      : filename_(fuzzer_get_tmpfile(data, size)) { }

  ~FuzzerTemporaryFile() {
    fuzzer_release_tmpfile(filename_);
  }

  const char* filename() const { return filename_; }

 private:
  char* filename_;
};
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const FuzzerTemporaryFile file(data, size);
  try {
    cv::Mat matrix = cv::imread(file.filename());
  } catch (cv::Exception e) {
    // Do nothing.
  }
  return 0;
}

