// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdint>
#include <poppler-qt5.h>
#include <QtCore/QBuffer>

static void dummy_error_function(const QString &, const QVariant &) { }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Poppler::setDebugErrorFunction(dummy_error_function, QVariant());
    const QFont font(QStringLiteral("Helvetica"), 20);
    const QColor color = QColor::fromRgb(0xAB, 0xCD, 0xEF);

    QByteArray in_data = QByteArray::fromRawData((const char *)data, size);
    Poppler::Document *doc = Poppler::Document::loadFromData(in_data);

    if (!doc || doc->isLocked()) {
        delete doc;
        return 0;
    }

    for (int i = 0; i < doc->numPages(); i++) {
        Poppler::Page *p = doc->page(i);
        if (!p) {
            continue;
        }
        Poppler::TextAnnotation *ann = new Poppler::TextAnnotation(Poppler::TextAnnotation::InPlace);
        ann->setTextFont(font);
        ann->setTextColor(color);
        ann->setBoundary(QRectF(0.1, 0.1, 0.2, 0.2));
        ann->setContents(QString(in_data));
        p->addAnnotation(ann);

        QBuffer buffer;
        buffer.open(QIODevice::WriteOnly);
        std::unique_ptr<Poppler::PDFConverter> conv(doc->pdfConverter());
        conv->setOutputDevice(&buffer);
        conv->setPDFOptions(Poppler::PDFConverter::WithChanges);
        conv->convert();
        buffer.close();
        delete ann;
        delete p;
    }

    delete doc;
    return 0;
}
