/*
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
