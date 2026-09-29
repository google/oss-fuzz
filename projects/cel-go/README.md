# CEL-Go Fuzzing

This directory contains OSS-Fuzz integration and fuzz targets for CEL-Go:

- `fuzz_compile`: Fuzzes expression compilation and program creation.
- `fuzz_eval`: Structure-aware libprotobuf-mutator fuzzer for variable evaluation.
- `fuzz_pratt_parser`: Differential fuzzer comparing ANTLR and Pratt parser outputs.

---

## Requirements & Setup

OSS-Fuzz uses Docker (or Podman) via `infra/helper.py`.

### Using Podman as an Alternative to Docker

If using `podman` instead of `docker`, create a `docker` symlink on your `PATH`:

```bash
mkdir -p /tmp/bin
ln -sf $(which podman) /tmp/bin/docker
export PATH="/tmp/bin:$PATH"
```

---

## Running Fuzzers Locally

To build and run fuzzers against the remote `cel-expr/cel-go` repository:

```bash
# Navigate to oss-fuzz root directory
cd /local/oss-fuzz

# 1. Build the fuzzer container image and compile fuzz binaries
python3 infra/helper.py build_fuzzers cel-go

# 2. Run a fuzzer (e.g. fuzz_pratt_parser for 30 seconds)
python3 infra/helper.py run_fuzzer cel-go fuzz_pratt_parser -- -max_total_time=30
```

---

## Running Fuzzers Against a Local Clone of `cel-expr/cel-go`

To test local changes or feature branches in your working tree without pushing to GitHub, mount your local repository path (e.g. `/local/cel-go`) into the build container via `build_fuzzers`:

```bash
cd /local/oss-fuzz

# 1. Build fuzzers mounting local /local/cel-go
python3 infra/helper.py build_fuzzers cel-go /local/cel-go

# 2. Run the differential fuzzer
python3 infra/helper.py run_fuzzer cel-go fuzz_pratt_parser -- -max_total_time=30
```
