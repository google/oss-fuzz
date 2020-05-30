/*
# Copyright 2020 Google Inc.
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libxml.h"
#include "libxml/xpath.h"
#include "libxml/parser.h"
#include "libxml/parserInternals.h"
#include "libxml/xpathInternals.h"
#include "libxml/xmlerror.h"
#include "libxml/globals.h"
#include "libxml/xpointer.h"
#include "libxml/xmlreader.h"


void ignore (void* ctx, const char* msg, ...) {
  // Error handler to avoid spam of error messages from libxml parser.
}


/* The goal is to fuzz the xpath logic so we maintain a template HTML
 * file here to help the focus and performance of the fuzzer */
static xmlChar buffer[] =
"<?xml version=\"1.0\"?>\n\
<EXAMPLE prop1=\"gnome is great\" prop2=\"&amp; linux too\">\n\
  <head>\n\
   <title>Welcome to Gnome</title>\n\
  </head>\n\
  <chapter>\n\
   <title>The Linux adventure</title>\n\
   <p>bla bla bla ...</p>\n\
   <image href=\"linus.gif\"/>\n\
   <p>...</p>\n\
  </chapter>\n\
  <chapter>\n\
   <title>Chapter 2</title>\n\
   <p>this is chapter 2 ...</p>\n\
  </chapter>\n\
  <chapter>\n\
   <title>Chapter 3</title>\n\
   <p>this is chapter 3 ...</p>\n\
  </chapter>\n\
</EXAMPLE>\n\
";


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    xmlSetGenericErrorFunc(NULL, &ignore);

    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
        return 0;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\0';

    // Read the template HTML document
    xmlDocPtr document = NULL;
    document = xmlReadDoc(buffer,NULL,NULL,XML_PARSE_COMPACT);

    // Main fuzzing logic
    xmlXPathContextPtr ctxt;
    xmlXPathObjectPtr res;

    ctxt = xmlXPathNewContext(document);
    ctxt->node = xmlDocGetRootElement(document);
    res = xmlXPathEvalExpression(BAD_CAST new_str, ctxt);

    // Cleanup
    xmlXPathFreeObject(res);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(document);
    xmlCleanupParser();
    xmlMemoryDump();

    free(new_str);

    return EXIT_SUCCESS;
}
