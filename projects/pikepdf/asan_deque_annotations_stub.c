/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************
 *
 * Workaround for https://github.com/google/oss-fuzz/issues/12839.
 *
 * Python fuzzers built with compile_python_fuzzer do not link the toolchain's
 * ASan runtime; instead the generated launcher LD_PRELOADs
 * sanitizer_with_fuzzer.so, which is the prebuilt asan_with_fuzzer.so that
 * ships inside the atheris wheel. That runtime is older than the clang in the
 * base image and does not export libc++'s double-ended (std::deque) container
 * annotation entry points. libqpdf and pikepdf._core are compiled with the
 * image's libc++, which emits calls to them unconditionally under
 * __has_feature(address_sanitizer) -- there is no compile-time switch to turn
 * the annotations off. The result is that dlopen()ing libqpdf.so fails with
 *
 *   undefined symbol: __sanitizer_annotate_double_ended_contiguous_container
 *
 * and every fuzz target dies during `import pikepdf`.
 *
 * These weak no-op definitions satisfy the link. They only disable ASan's
 * container-overflow detection *inside* std::deque's allocated-but-unused
 * region; all other ASan checking (heap/stack/global overflows, UAF, ...) is
 * unaffected, and the redzones stay unpoisoned, so no false positives are
 * introduced. Because these live in a dlopen()ed library, the LD_PRELOADed
 * runtime's definitions take precedence in the global symbol scope, so this
 * automatically becomes dead weight once atheris ships a newer ASan runtime.
 */

__attribute__((weak)) void __sanitizer_annotate_double_ended_contiguous_container(
    const void *first_storage, const void *last_storage,
    const void *first_old_contained, const void *last_old_contained,
    const void *first_new_contained, const void *last_new_contained) {
  (void)first_storage;
  (void)last_storage;
  (void)first_old_contained;
  (void)last_old_contained;
  (void)first_new_contained;
  (void)last_new_contained;
}

/* Returns "the container is consistently annotated". With annotations disabled
 * that is vacuously true. */
__attribute__((weak)) int __sanitizer_verify_double_ended_contiguous_container(
    const void *first_storage, const void *first_contained,
    const void *last_contained, const void *last_storage) {
  (void)first_storage;
  (void)first_contained;
  (void)last_contained;
  (void)last_storage;
  return 1;
}
