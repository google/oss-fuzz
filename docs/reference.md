# Reference

## Sanitizers

Fuzzers are usualy built with one or more  [sanitizer](https://github.com/google/sanitizers) enabled. 
You can select sanitizer configuration by specifying `$SANITIZER` build environment varible using `-e` option:

```bash
python infra/helper.py build_fuzzers -e SANITIZER=undefined json
```

Supported sanitizers:

| `$SANITIZER` | Description
| ------------ | ----------
| `address` *(default)* | [Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer) with [Leak Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizerLeakSanitizer).
| `undefined` | [Undefined Behavior Sanitizer](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
| `memory` | [Memory Sanitizer](https://github.com/google/sanitizers/wiki/MemorySanitizer). *NOTE: It is critical that you build __all__ the code in your program (including libraries it uses) with memory sanitizer.*

Compiler flag values for predefined configurations are specified in the [Dockerfile](../base-images/base-builder/Dockerfile). 
These flags can be overriden by specifying `$SANITIZER_FLAGS` directly.

You can choose which configurations to automatically run your fuzzers with in `project.yaml` file ([sqlite3](../../../projects/sqlite3/project.yaml)):

```yaml
sanitizers:
  - address
  - undefined
 ```
  
