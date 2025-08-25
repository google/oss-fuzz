# Shared translation code

This directory contains the JS-to-C++ translation of fuzzer callbacks that is
shared between the libfuzzer addon (for in-process fuzzing) and the native agent
addon (for out-of-process fuzzing).

## Rationale

Our instrumentor component always works the same way, no matter whether it's
used for in-process or out-of-process fuzzing. It inserts calls to JS functions
into target code (e.g., to record string comparisons); ultimately, we want the
calls to reach libfuzzer (in-process fuzzing) or the native agent
(out-of-process fuzzing).

While it would be the most convenient to do the JS-to-C++ translation only once,
inside the instrumentor, and then link against one of the two addons, Node
doesn't allow sharing of C symbols between addons. (Concretely, it loads native
addons with `RTLD_LOCAL`.) Therefore, we include the translation layer in both
addons, so that the instrumentor can use the JS functions corresponding to the
fuzzer callbacks after importing either the libfuzzer addon or the native agent
addon.

## Usage

Note that this directory doesn't contain a CMake project; it just provides
library code, to be linked and used from the parent CMake projects (i.e., the
projects for the two addons). Currently, the code lives in `packages/fuzzer`
because the native agent addon hasn't been built yet; it can later by symlinked
into the native agent addon and possibly moved somewhere outside either package.
If more advanced use cases come up, we can think about adding a CMake
configuration and exporting a static library, but for now it should be fine to
just reference the source files from the parent projects.
