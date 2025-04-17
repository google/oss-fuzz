# OSS-Fuzz: Continuous Fuzzing for Open Source Software

## Setup

1. Clone the submodule (the libxml2 library):
```bash
git submodule update --init --recursive
```

2. Build the libxml2 image:
```bash
python3 infra/helper.py build_image libxml2
```

The fuzzers are built from the `libxml2/fuzz/` directory.

3. Build the fuzzers:
```bash
python3 infra/helper.py build_fuzzers libxml2
mkdir -p build/out/corpus
```

4. Run a fuzzer:
```bash
python3 infra/helper.py run_fuzzer libxml2 <fuzzer> --corpus-dir build/out/corpus
```
