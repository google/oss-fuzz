/*
# SPDX-FileCopyrightText: 2025 Google LLC
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2025 Google LLC
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
*/

/*
  Usage:
    python infra/helper.py build_image karchive
    python infra/helper.py build_fuzzers --sanitizer undefined|address|memory karchive
    python infra/helper.py run_fuzzer karchive ktar_[gz|bz2|xz|zst|lz]_fuzzer
*/

#include <QBuffer>
#include <QCoreApplication>

#include <kcompressiondevice.h>
#include <ktar.h>

#include "karchive_fuzzer_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int argc = 0;
    QCoreApplication a(argc, nullptr);

    QBuffer b;
    b.setData((const char *)data, size);

#ifdef HANDLER
    KCompressionDevice kd(&b, false, KCompressionDevice::HANDLER);
    KTar ktar(&kd);

    if (ktar.open(QIODevice::ReadOnly)) {
        traverseArchive(ktar.directory());
        ktar.close();
    }
#endif

    return 0;
}
