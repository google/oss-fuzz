# OSS-Fuzz Integration for libmongocrypt

This directory contains the OSS-Fuzz integration for libmongocrypt.

## Overview

[OSS-Fuzz](https://github.com/google/oss-fuzz) is Google's continuous fuzzing service for open source software. This integration enables automated fuzzing of libmongocrypt to discover potential security vulnerabilities and bugs.

## Files

- **Dockerfile**: Defines the build environment for OSS-Fuzz
- **build.sh**: Script that builds libmongocrypt and the fuzzing targets
- **project.yaml**: OSS-Fuzz project configuration

## Fuzzing Targets

### fuzz_kms
Fuzzes the KMS message parsing and request creation functionality.
- Source: `test/fuzz_kms.c`
- Targets: `kms_response_parser_feed()`, `kms_request_new()`

### fuzz_mongocrypt (Placeholder)
Main fuzzer for libmongocrypt encryption/decryption APIs.
- Source: `test/fuzz_mongocrypt.c`
- Status: **Placeholder** - needs implementation
- Planned targets:
  - `mongocrypt_ctx_encrypt_init()` with fuzzed BSON commands
  - `mongocrypt_ctx_decrypt_init()` with fuzzed encrypted data
  - `mongocrypt_ctx_explicit_encrypt_init()` with fuzzed values
  - `mongocrypt_ctx_explicit_decrypt_init()` with fuzzed ciphertext
  - `mongocrypt_ctx_mongo_feed()` with fuzzed BSON documents
  - `mongocrypt_kms_ctx_feed()` with fuzzed KMS responses

## Local Testing

To test the OSS-Fuzz integration locally:

```bash
# Clone OSS-Fuzz
git clone https://github.com/google/oss-fuzz.git
cd oss-fuzz

# Copy the libmongocrypt OSS-Fuzz files
cp -r /path/to/libmongocrypt/oss-fuzz projects/libmongocrypt

# Build the Docker image
python infra/helper.py build_image libmongocrypt

# Build the fuzzers
python infra/helper.py build_fuzzers libmongocrypt

# Run a fuzzer
python infra/helper.py run_fuzzer libmongocrypt fuzz_kms
```

## Integration with OSS-Fuzz Repository

To integrate with the official OSS-Fuzz repository:

1. Fork the [OSS-Fuzz repository](https://github.com/google/oss-fuzz)
2. Copy the files from this directory to `projects/libmongocrypt/` in the OSS-Fuzz repo
3. Test locally using the commands above
4. Submit a pull request to the OSS-Fuzz repository

See the [OSS-Fuzz New Project Guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/) for detailed instructions.

## TODO

- [ ] Implement comprehensive fuzzing logic in `fuzz_mongocrypt.c`
- [ ] Add seed corpus for better fuzzing coverage
- [ ] Add dictionary files for BSON fuzzing
- [ ] Test with all sanitizers (ASan, UBSan, MSan)
- [ ] Add additional fuzzing targets for specific APIs
- [ ] Configure continuous integration with OSS-Fuzz

## References

- [OSS-Fuzz Documentation](https://google.github.io/oss-fuzz/)
- [libFuzzer Tutorial](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [libmongocrypt Documentation](https://github.com/mongodb/libmongocrypt)

