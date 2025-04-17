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

3. Build the fuzzers:
```bash
python3 infra/helper.py build_fuzzers libxml2
mkdir -p build/out/corpus
```