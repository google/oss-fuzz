/*
# SPDX-FileCopyrightText: 2019 Google Inc.
# SPDX-FileCopyrightText: 2025 Azhar Momin <azhar.momin@kdemail.net>
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2019 Google Inc.
# Copyright 2025 Azhar Momin <azhar.momin@kdemail.net>
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
    python infra/helper.py run_fuzzer karchive k[ar|tar|zip|7z]_fuzzer
*/

#include <QBuffer>
#include <QCoreApplication>

#include <k7zip.h>
#include <kar.h>
#include <ktar.h>
#include <kzip.h>

#include "karchive_fuzzer_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int argc = 0;
    QCoreApplication a(argc, nullptr);

    QBuffer b;
    b.setData((const char *)data, size);

#ifdef HANDLER
    HANDLER handler(&b);

#ifdef USE_PASSWORD
    handler.setPassword("youshallnotpass");
#endif

    if (handler.open(QIODevice::ReadOnly)) {
        traverseArchive(handler.directory());
        handler.close();
    }
#endif

    return 0;
}
