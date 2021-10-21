#!/bin/bash
# Build and install project (using current CFLAGS, CXXFLAGS). This is required
# for projects with C extensions so that they're built with the proper flags.
pip3 install .

# Build fuzzers into $OUT. These could be detected in other ways.
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  # To avoid issues with Python version conflicts, or changes in environment
  # over time on the OSS-Fuzz bots, we use pyinstaller to create a standalone
  # package. Though not necessarily required for reproducing issues, this is
  # required to keep fuzzers working properly in OSS-Fuzz.
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # Create execution wrapper. Atheris requires that certain libraries are
  # preloaded, so this is also done here to ensure compatibility and simplify
  # test case reproduction. Since this helper script is what OSS-Fuzz will
  # actually execute, it is also always required.
  # NOTE: If you are fuzzing python-only code and do not have native C/C++
  # extensions, then remove the LD_PRELOAD line below as preloading sanitizer
  # library is not required and can lead to unexpected startup crashes.
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_PRELOAD=\$this_dir/sanitizer_with_fuzzer.so \
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \
\$this_dir/$fuzzer_package \$@" > $OUT/$fuzzer_basename
  chmod +x $OUT/$fuzzer_basename
done
