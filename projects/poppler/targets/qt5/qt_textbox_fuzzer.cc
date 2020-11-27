#include <cstdint>
#include <poppler-qt5.h>
#include <QtGui/QImage>
#include <QtGui/QPainter>

static void dummy_error_function(const QString &, const QVariant &) { }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Poppler::setDebugErrorFunction(dummy_error_function, QVariant());
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
        QRectF rf = QRectF(0.0, 0.0, 1.0, 1.0);
        Poppler::TextBox tb(QString(in_data), rf);
        QImage image = p->renderToImage(72.0, 72.0, -1, -1, -1, -1, Poppler::Page::Rotate0);
        QPainter painter(&image);
        painter.drawRect(tb.boundingBox());
        delete p;
    }
    delete doc;
    return 0;
}
