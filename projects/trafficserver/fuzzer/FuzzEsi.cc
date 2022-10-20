#include <iostream>
#include <cassert>
#include <string>

#include "EsiParser.h"

using std::string;
using namespace EsiLib;

#define kMinInputLength 5
#define kMaxInputLength 1024

void
Debug(const char *tag, const char *fmt, ...)
{
    return;
}

void
Error(const char *fmt, ...)
{
    return;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*trafficserver/plugins/esi/test/docnode_test.cc*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    EsiParser parser("parser_test", &Debug, &Error);

    bool ret;
    DocNodeList node_list;
    string input_data((char *)Data,Size);

    ret = parser.completeParse(node_list, input_data);

    if(ret == true){
        DocNodeList node_list2;
        string packed = node_list.pack();
        node_list2.unpack(packed);
        node_list2.clear();
    }

    node_list.clear();

    return ret;
}
