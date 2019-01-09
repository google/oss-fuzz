#!/bin/bash -eu
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

pushd $SRC/Python-2.7.15/
patch -p1 <<'EOF'
Index: v2_7_unstable/Python/pymath.c
===================================================================
--- v2_7_unstable.orig/Python/pymath.c
+++ v2_7_unstable/Python/pymath.c
@@ -18,6 +18,7 @@ double _Py_force_double(double x)
 /* inline assembly for getting and setting the 387 FPU control word on
    gcc/x86 */

+__attribute__((no_sanitize_memory))
 unsigned short _Py_get_387controlword(void) {
     unsigned short cw;
     __asm__ __volatile__ ("fnstcw %0" : "=m" (cw));
Index: v2_7_unstable/Modules/_ctypes/callproc.c
===================================================================
--- v2_7_unstable.orig/Modules/_ctypes/callproc.c
+++ v2_7_unstable/Modules/_ctypes/callproc.c
@@ -1166,6 +1166,10 @@ PyObject *_ctypes_callproc(PPROC pProc,

     rtype = _ctypes_get_ffi_type(restype);
     resbuf = alloca(max(rtype->size, sizeof(ffi_arg)));
+    /* ffi_call actually initializes resbuf, but from asm, which
+     * MemorySanitizer can't detect. Avoid false positives from MSan. */
+    if (resbuf != NULL)
+        memset(resbuf, 0, max(rtype->size, sizeof(ffi_arg)));

     avalues = (void **)alloca(sizeof(void *) * argcount);
     atypes = (ffi_type **)alloca(sizeof(ffi_type *) * argcount);
EOF

if [ -e $OUT/sanpy/cflags -a "$(cat $OUT/sanpy/cflags)" = "${CFLAGS}" ] ; then
    echo 'Python cflags unchanged, no need to rebuild'
else
    rm -rf $OUT/sanpy
    ASAN_OPTIONS=detect_leaks=0 ./configure --without-pymalloc \
                --prefix=$OUT/sanpy CFLAGS="${CFLAGS}" LINKCC="${CXX}" \
                LDFLAGS="${CXXFLAGS}"
    grep -v HAVE_GETC_UNLOCKED < pyconfig.h > tmp && mv tmp pyconfig.h
    ASAN_OPTIONS=detect_leaks=0 make && make install
    echo "${CFLAGS}" > $OUT/sanpy/cflags
fi
popd

cd contrib/fuzz
make clean oss-fuzz
