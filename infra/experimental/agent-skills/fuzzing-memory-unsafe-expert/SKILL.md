---
name: fuzzing-memory-unsafe-expert
description:
  Use this skill to fuzz open source C/C++ software projects.
---

# Fuzzing memory-unsafe expert

This skill provides the agent with the necessary knowledge and tools to fuzz open source software projects, particularly those that are part of the OSS-Fuzz program. The agent can use this skill to build fuzzers, run fuzzing campaigns, analyze results, and improve the fuzzing posture of projects.

The fuzzing abilities focused on here is libFuzzer-style harnesses, which are commonly used in OSS-Fuzz.

## Fundamental Concepts

### Fuzzing harness core function

A fuzzing harness is a function that takes a byte array as input and processes it in a way that can trigger bugs or vulnerabilities in the software being tested. The core function of a fuzzing harness typically looks like this:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Process the input data and trigger potential bugs
    return 0; // Return 0 to indicate successful processing
}
```

### Characteristics found in good fuzzing harnesses

The below are characteristics commonly found in good fuzzing harnesses, which contribute to their effectiveness in finding bugs. They are not all necessary for a good harness and at times it may even be desirable to actively not pursue some of them.

1. **Simplicity**: The harness should be simple and focused on processing the input data without unnecessary complexity.
2. **Coverage**: The harness should aim to cover as much of the codebase as possible, including edge cases and error handling paths.
3. **Determinism**: The harness should produce consistent results for the same input, allowing for reliable reproduction of bugs.
4. **Performance**: The harness should be efficient in processing inputs to maximize the number of test cases that can be executed in a given time frame.
5. **Error Handling**: The harness should include robust error handling to capture and report any issues that arise during fuzzing.
6. **True Positives**: The harness should be designed to have no false positives, ensuring that reported issues are genuine bugs. This means all issues found by the fuzzer is something the maintainers are interested in fixing.
7. **Matches threat model**: The harness should be designed to target specific types of vulnerabilities that are relevant to the project being fuzzed.
8. **Hits code on the attack surface**: The harness should be designed to target code that is exposed to untrusted input, such as network interfaces, file parsers, or APIs.
9. **Enough entropy**: The harness should be designed to allow for a wide range of inputs, providing enough variability to trigger different code paths and potential bugs.
10. **Follows the code structure**: The harness should be designed to follow the structure of the codebase, making it easier to identify and target specific areas of interest.
11. **Follows code conventions**: The harness should follow the coding conventions of the project, making it easier for maintainers to understand and integrate the harness into the codebase.
12. **Does not get stuck**: The harness should be designed to avoid getting stuck on certain inputs or code paths, allowing the fuzzer to continue exploring other areas of the codebase.
13. **Includes dictionary**: The harness should include a dictionary of known inputs or patterns that are relevant to the project, helping the fuzzer to generate more effective test cases.