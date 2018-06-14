# Reference

## Sanitizers

Fuzzers are usually built with one or more  [sanitizer](https://github.com/google/sanitizers) enabled. 
You can select sanitizer configuration by specifying `$SANITIZER` build environment variable using `-e` option:

```bash
python infra/helper.py build_fuzzers --sanitizer undefined json
```

Supported sanitizers:

| `$SANITIZER` | Description
| ------------ | ----------
| `address` *(default)* | [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer) with [Leak Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer).
| `undefined` | [Undefined Behavior Sanitizer](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
| `memory` | [Memory Sanitizer](https://github.com/google/sanitizers/wiki/MemorySanitizer).<br/>*NOTE: It is critical that you build __all__ the code in your program (including libraries it uses) with Memory Sanitizer. Otherwise, you will see false positive crashes due to an inability to see initializations in uninstrumented code.*
| `profile` | Used for generating code coverage reports. See [Code Coverage doc](code_coverage.md).

Compiler flag values for predefined configurations are specified in the [Dockerfile](../infra/base-images/base-builder/Dockerfile). 
These flags can be overriden by specifying `$SANITIZER_FLAGS` directly.

You can choose which configurations to automatically run your fuzzers with in `project.yaml` file (e.g. [sqlite3](../projects/sqlite3/project.yaml)):

```yaml
sanitizers:
  - address
  - undefined
```
