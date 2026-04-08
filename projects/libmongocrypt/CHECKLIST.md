# OSS-Fuzz Implementation Checklist

Use this checklist to track progress on implementing the OSS-Fuzz integration.

## Phase 1: Setup and Verification ✅

- [x] Create OSS-Fuzz configuration files
  - [x] Dockerfile
  - [x] build.sh
  - [x] project.yaml
- [x] Create placeholder fuzzer (`test/fuzz_mongocrypt.c`)
- [x] Create documentation
  - [x] README.md
  - [x] INTEGRATION_GUIDE.md
  - [x] SUMMARY.md
- [x] Create local testing script
- [x] Make scripts executable

## Phase 2: Local Testing

- [ ] Test local build
  ```bash
  cd oss-fuzz
  ./test_build_local.sh
  ```
- [ ] Verify fuzzers compile without errors
- [ ] Run placeholder fuzzer to ensure it executes
  ```bash
  ./out/fuzz_mongocrypt -max_total_time=10
  ```
- [ ] Verify existing fuzz_kms works
  ```bash
  ./out/fuzz_kms -max_total_time=10
  ```

## Phase 3: Implement Fuzzing Logic

### 3.1 Basic Implementation
- [ ] Add KMS provider configuration
  - [ ] Create minimal valid KMS config
  - [ ] Handle initialization errors gracefully
- [ ] Implement basic encryption fuzzing
  - [ ] Fuzz `mongocrypt_ctx_encrypt_init()`
  - [ ] Handle BSON parsing errors
  - [ ] Test with valid BSON samples
- [ ] Implement basic decryption fuzzing
  - [ ] Fuzz `mongocrypt_ctx_decrypt_init()`
  - [ ] Handle invalid ciphertext gracefully

### 3.2 Advanced Implementation
- [ ] Add explicit encryption fuzzing
  - [ ] Fuzz `mongocrypt_ctx_explicit_encrypt_init()`
  - [ ] Test different algorithms
  - [ ] Test different key IDs
- [ ] Add KMS context fuzzing
  - [ ] Fuzz `mongocrypt_kms_ctx_feed()`
  - [ ] Test different KMS providers
- [ ] Add BSON document feeding
  - [ ] Fuzz `mongocrypt_ctx_mongo_feed()`
  - [ ] Test collection info documents
  - [ ] Test key documents

### 3.3 Input Partitioning
- [ ] Implement input splitting strategy
  - [ ] Reserve bytes for operation selection
  - [ ] Reserve bytes for configuration
  - [ ] Reserve bytes for BSON data
- [ ] Add input validation
  - [ ] Check minimum sizes
  - [ ] Validate BSON structure
- [ ] Handle edge cases
  - [ ] Empty inputs
  - [ ] Very large inputs
  - [ ] Malformed BSON

## Phase 4: Seed Corpus

- [ ] Create seed corpus directory
  ```bash
  mkdir -p oss-fuzz/seed_corpus
  ```
- [ ] Add valid BSON documents
  - [ ] Simple documents
  - [ ] Nested documents
  - [ ] Arrays
  - [ ] All BSON types
- [ ] Add encrypted data samples
  - [ ] FLE1 encrypted values
  - [ ] FLE2 encrypted values
  - [ ] Different algorithms
- [ ] Add KMS response samples
  - [ ] AWS KMS responses
  - [ ] Azure responses
  - [ ] GCP responses
  - [ ] Local KMS responses

## Phase 5: Dictionary

- [ ] Create BSON dictionary file
  ```bash
  touch oss-fuzz/mongocrypt.dict
  ```
- [ ] Add common field names
  - [ ] `"_id"`
  - [ ] `"keyId"`
  - [ ] `"algorithm"`
  - [ ] `"value"`
  - [ ] `"v"`
  - [ ] Add more from test data
- [ ] Add algorithm names
  - [ ] `"AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic"`
  - [ ] `"AEAD_AES_256_CBC_HMAC_SHA_512-Random"`
  - [ ] Add FLE2 algorithms

## Phase 6: Testing with Sanitizers

- [ ] Test with AddressSanitizer (ASan)
  ```bash
  # In test_build_local.sh, CFLAGS already includes ASan
  ./test_build_local.sh
  ./out/fuzz_mongocrypt -max_total_time=300
  ```
- [ ] Test with UndefinedBehaviorSanitizer (UBSan)
  ```bash
  # Modify CFLAGS in test_build_local.sh
  export CFLAGS="-g -O1 -fsanitize=undefined,fuzzer-no-link"
  ```
- [ ] Test with MemorySanitizer (MSan)
  ```bash
  # Requires clang and special build
  export CFLAGS="-g -O1 -fsanitize=memory,fuzzer-no-link"
  ```
- [ ] Fix any issues found
  - [ ] Document expected errors
  - [ ] Fix actual bugs
  - [ ] Add suppressions if needed

## Phase 7: OSS-Fuzz Integration Testing

- [ ] Clone OSS-Fuzz repository
  ```bash
  git clone https://github.com/google/oss-fuzz.git
  ```
- [ ] Copy files to OSS-Fuzz
  ```bash
  cp -r oss-fuzz/* oss-fuzz-repo/projects/libmongocrypt/
  ```
- [ ] Build with OSS-Fuzz infrastructure
  ```bash
  python infra/helper.py build_image libmongocrypt
  python infra/helper.py build_fuzzers libmongocrypt
  ```
- [ ] Run fuzzers
  ```bash
  python infra/helper.py run_fuzzer libmongocrypt fuzz_mongocrypt
  ```
- [ ] Check coverage
  ```bash
  python infra/helper.py coverage libmongocrypt
  ```
- [ ] Review coverage report
  - [ ] Identify uncovered code
  - [ ] Add tests for uncovered paths

## Phase 8: Submission

- [ ] Update project.yaml with correct contacts
  - [ ] Verify primary_contact email
  - [ ] Add auto_ccs emails
- [ ] Create PR to OSS-Fuzz
  - [ ] Fork OSS-Fuzz repository
  - [ ] Create branch
  - [ ] Commit files
  - [ ] Submit pull request
- [ ] Address review comments
- [ ] Wait for approval and merge

## Phase 9: Monitoring

- [ ] Set up bug notifications
- [ ] Monitor OSS-Fuzz dashboard
- [ ] Triage reported issues
- [ ] Fix bugs found by fuzzing
- [ ] Update seed corpus based on findings

## Notes

- Mark items as complete with `[x]`
- Add notes or blockers inline
- Update this checklist as needed
- Keep SUMMARY.md in sync with progress

