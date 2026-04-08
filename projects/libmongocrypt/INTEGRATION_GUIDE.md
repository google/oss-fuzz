# OSS-Fuzz Integration Guide for libmongocrypt

## Quick Start

This guide explains how to integrate libmongocrypt with OSS-Fuzz.

## What Has Been Created

### 1. Fuzzing Entry Points

#### `test/fuzz_mongocrypt.c` (NEW - Placeholder)
A placeholder fuzzer for the main libmongocrypt APIs. This file contains:
- Basic libFuzzer entry point (`LLVMFuzzerTestOneInput`)
- Extensive TODO comments with examples of how to fuzz different APIs
- Proper initialization and cleanup

**Status**: Placeholder only - needs actual fuzzing logic implementation

#### `test/fuzz_kms.c` (Existing)
Already exists and fuzzes KMS message parsing.

### 2. OSS-Fuzz Configuration Files

All files are in the `oss-fuzz/` directory:

#### `Dockerfile`
- Defines the build environment
- Installs dependencies (cmake, pkg-config, libssl-dev)
- Clones the libmongocrypt repository

#### `build.sh`
- Builds libmongocrypt with appropriate flags
- Compiles fuzzing targets
- Links against libFuzzer

#### `project.yaml`
- Project metadata (homepage, contacts, language)
- Sanitizer configuration (ASan, UBSan, MSan)
- Fuzzing engine configuration (libFuzzer, AFL, Honggfuzz)

## Next Steps

### Step 1: Implement the Fuzzer Logic

Edit `test/fuzz_mongocrypt.c` to add actual fuzzing logic. See the TODO comments for examples.

Key considerations:
- **Input partitioning**: Split the fuzzed input into multiple parts for different parameters
- **State management**: Handle the mongocrypt state machine properly
- **Error handling**: Don't crash on expected errors
- **Coverage**: Target multiple code paths

Example implementation approach:
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 100) return 0;
    
    // Partition input
    const uint8_t *kms_config = data;
    size_t kms_config_size = 50;
    const uint8_t *bson_data = data + 50;
    size_t bson_size = size - 50;
    
    // Initialize with fuzzed KMS config
    mongocrypt_t *crypt = mongocrypt_new();
    mongocrypt_binary_t *kms_bin = mongocrypt_binary_new_from_data(
        (uint8_t *)kms_config, kms_config_size);
    mongocrypt_setopt_kms_providers(crypt, kms_bin);
    mongocrypt_init(crypt);
    
    // Fuzz encryption
    mongocrypt_ctx_t *ctx = mongocrypt_ctx_new(crypt);
    mongocrypt_binary_t *doc_bin = mongocrypt_binary_new_from_data(
        (uint8_t *)bson_data, bson_size);
    mongocrypt_ctx_encrypt_init(ctx, "db", -1, doc_bin);
    
    // Cleanup
    mongocrypt_binary_destroy(doc_bin);
    mongocrypt_binary_destroy(kms_bin);
    mongocrypt_ctx_destroy(ctx);
    mongocrypt_destroy(crypt);
    
    return 0;
}
```

### Step 2: Create Seed Corpus

Create a directory with sample inputs:
```bash
mkdir -p oss-fuzz/seed_corpus
```

Add valid BSON documents and encrypted data as seed inputs. These help the fuzzer understand the input format.

### Step 3: Create Dictionary (Optional)

Create `oss-fuzz/mongocrypt.dict` with common BSON field names:
```
"_id"
"keyId"
"algorithm"
"value"
"v"
"encrypted"
```

### Step 4: Test Locally

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Create project directory
mkdir -p projects/libmongocrypt

# Copy files
cp /path/to/libmongocrypt/oss-fuzz/* projects/libmongocrypt/

# Build
python infra/helper.py build_image libmongocrypt
python infra/helper.py build_fuzzers libmongocrypt

# Run
python infra/helper.py run_fuzzer libmongocrypt fuzz_mongocrypt -- -max_total_time=60
```

### Step 5: Submit to OSS-Fuzz

1. Test all sanitizers:
   ```bash
   python infra/helper.py build_fuzzers --sanitizer address libmongocrypt
   python infra/helper.py build_fuzzers --sanitizer undefined libmongocrypt
   python infra/helper.py build_fuzzers --sanitizer memory libmongocrypt
   ```

2. Run coverage check:
   ```bash
   python infra/helper.py coverage libmongocrypt
   ```

3. Submit PR to https://github.com/google/oss-fuzz

## Troubleshooting

### Build Failures

- Check that all dependencies are in the Dockerfile
- Verify library paths in build.sh
- Ensure static libraries are being built

### Runtime Crashes

- Use `run_fuzzer` with `-help=1` to see libFuzzer options
- Add `-print_final_stats=1` for debugging
- Check sanitizer output for actual bugs vs. expected errors

### Low Coverage

- Add more seed corpus files
- Implement multiple fuzzing targets
- Use coverage report to identify untested code

## Resources

- [OSS-Fuzz Documentation](https://google.github.io/oss-fuzz/)
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [Fuzzing BSON](https://github.com/mongodb/mongo/tree/master/src/third_party/libfuzzer)

