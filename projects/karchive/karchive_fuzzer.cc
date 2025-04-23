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

#include <KF6/KArchive/k7zip.h>
#include <KF6/KArchive/ktar.h>
#include <KF6/KArchive/kzip.h>
#include <KF6/KArchive/kar.h>
#include <KF6/KArchive/kcompressiondevice.h>

void traverseArchive(const KArchiveDirectory *dir, const QString &path = QString()) {
    const auto allEntries = dir->entries();

    for (const auto& entryName : allEntries) {
        auto entry = dir->entry(entryName);
        const QString fullPath = path + QString::fromUtf8("/") + entryName;

        if (entry->isFile()) {
            auto file = static_cast<const KArchiveFile*>(entry);
            auto fullpath = fullPath.toStdString();
            auto filesize =  file->size();
            auto datasize = file->data().size();
            auto date =  file->date().toString().toStdString();
            auto filename = file->name().toStdString();
            auto user = file->user().toStdString();
            auto group = file->group().toStdString();
        } else if (entry->isDirectory()) {
            auto subDir = static_cast<const KArchiveDirectory*>(entry);
            traverseArchive(subDir, fullPath);
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int argc = 0;
    QCoreApplication a(argc, nullptr);

    QBuffer b;
    b.setData(QByteArray((const char *)data, size));

    std::unique_ptr<KCompressionDevice> gzipKD(new KCompressionDevice(&b, false, KCompressionDevice::GZip));
    std::unique_ptr<KCompressionDevice> bzipKD(new KCompressionDevice(&b, false, KCompressionDevice::BZip2));
    std::unique_ptr<KCompressionDevice> xzKD(new KCompressionDevice(&b, false, KCompressionDevice::Xz));
    std::unique_ptr<KCompressionDevice> zstdKD(new KCompressionDevice(&b, false, KCompressionDevice::Zstd));

    const QVector<KArchive*> handlers = {
        new K7Zip(&b),
        new KTar(&b),
        new KTar(gzipKD.get()),
        new KTar(bzipKD.get()),
        new KTar(xzKD.get()),
        new KTar(zstdKD.get()),
        new KZip(&b),
        new KAr(&b)
    };

    for (KArchive *h : handlers) {
        if (b.isOpen()) {
            b.reset();
        }

        if (auto k7zip = dynamic_cast<K7Zip *>(h)) {
            // Set a dummy password to trigger decryption code
            k7zip->setPassword("youshallnotpass");
        }

        if (h->open(QIODevice::ReadOnly)) {
            const KArchiveDirectory *rootDir = h->directory();
            traverseArchive(rootDir); 
            h->close();
        }
    }

    qDeleteAll(handlers);

    return 0;
}
