#!/usr/bin/env python3

"""Note: This is not a source file that is built and run as part of the build.

It is copied into the OSS-Fuzz container image and run there as part of the
instrumentation process.
"""

import os
import shutil
import subprocess


def main():
  # Copy fuzzing_engine.cc to the src directory so it is available to the
  # indexer.
  shutil.copyfile("/untitled/fuzzing_engine.cc",
                  "/src/untitled_fuzzing_engine.cc")

  # Compile and link the fuzzing engine.
  print('NILVO ESTEVE AQUI')
  subprocess.run([
      "/clang++",
      "-c",
      "-Wall",
      "-Wextra",
      "-pedantic",
      "-std=c++20",
      "-glldb",
      "-O0",
      "/src/untitled_fuzzing_engine.cc",
      "-o",
      "/out/untitled_fuzzing_engine.o",
      "-gen-cdb-fragment-path", "/out/cdb", "-Qunused-arguments",
      # "--sysroot=/sysroot",
      "-I/usr/grte/v5/include/",
      # "-I/toolchain/lib/clang/google3-trunk/include",
      # "-I/toolchain/include/c++/v1/",
  ], capture_output=False, check=True)

  subprocess.run([
      "ar",
      "rcs",
      "/untitled/fuzzing_engine.a",
      "/out/untitled_fuzzing_engine.o",
  ], capture_output=False, check=True)

  # Set up the symlink to the fuzzing engine.
  try:
    os.unlink("/usr/lib/libFuzzingEngine.a")
  except FileNotFoundError:
    pass

  os.symlink("/untitled/fuzzing_engine.a", "/usr/lib/libFuzzingEngine.a")

  # Run the main OSS-Fuzz compile script.
  subprocess.run(["/usr/local/bin/compile"], capture_output=False, check=True)

  for root, dirs, files in os.walk("/out"):
    for dir_name in dirs:
      dir_path = os.path.join(root, dir_name)
      os.chmod(dir_path, 0o755)
    for file_name in files:
      file_path = os.path.join(root, file_name)
      if os.access(file_path, os.X_OK):
        os.chmod(file_path, 0o755)
      else:
        os.chmod(file_path, 0o644)


if __name__ == "__main__":
  main()