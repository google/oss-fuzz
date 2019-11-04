#include "xerces_fuzz_common.h"

using namespace xercesc_3_2;
static bool initialized = false;

void parseInMemory(const uint8_t *Data, size_t Size)
{
    if (!initialized)
    {
        XMLPlatformUtils::Initialize();
        initialized = true;
    }
    SAXParser::ValSchemes valScheme = SAXParser::Val_Auto;
    bool doNamespaces = false;
    bool doSchema = false;
    bool schemaFullChecking = false;
    SAXParser *parser = new SAXParser;
    parser->setValidationScheme(valScheme);
    parser->setDoNamespaces(doNamespaces);
    parser->setDoSchema(doSchema);
    parser->setHandleMultipleImports(true);
    parser->setValidationSchemaFullChecking(schemaFullChecking);
    static const char *gMemBufId = "prodInfo";

    MemBufInputSource *memBufIS = new MemBufInputSource(
        (const XMLByte *)Data, Size, gMemBufId, false);
    parser->parse(*memBufIS);
    delete parser;
    delete memBufIS;
    //XMLPlatformUtils::Terminate();
}
