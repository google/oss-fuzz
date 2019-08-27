/*
# Copyright 2019 Google Inc.
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
    python infra/helper.py run_fuzzer karchive karchive_fuzzer
*/


#include <QBuffer>
#include <QCoreApplication>
#include <QVector>

#include <KF5/KArchive/k7zip.h>
#include <KF5/KArchive/ktar.h>
#include <KF5/KArchive/kzip.h>
#include <KF5/KArchive/kar.h>
#include <KF5/KArchive/kcompressiondevice.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int argc = 0;
    QCoreApplication a(argc, nullptr);

    QBuffer b;
    b.setData((const char *)data, size);

    std::unique_ptr<KCompressionDevice> gzipKD(new KCompressionDevice(&b, false, KCompressionDevice::GZip));
    std::unique_ptr<KCompressionDevice> bzipKD(new KCompressionDevice(&b, false, KCompressionDevice::BZip2));
    std::unique_ptr<KCompressionDevice> xzKD(new KCompressionDevice(&b, false, KCompressionDevice::Xz));

    const QVector<KArchive*> handlers = {
        new K7Zip(&b),
        new KTar(&b),
        new KTar(gzipKD.get()),
        new KTar(bzipKD.get()),
        new KTar(xzKD.get()),
        new KZip(&b),
        new KAr(&b)
    };

    for (KArchive *h : handlers) {
        b.reset();
        h->open(QIODevice::ReadOnly);
        h->close();
    }

    qDeleteAll(handlers);

    return 0;
}
