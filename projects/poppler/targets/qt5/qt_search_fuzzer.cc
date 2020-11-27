#include <cstdint>
#include <poppler-qt5.h>

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
        QString text = QString(in_data);
        p->search(text, Poppler::Page::IgnoreCase, Poppler::Page::Rotate0);
        delete p;
    }

    delete doc;
    return 0;
}
