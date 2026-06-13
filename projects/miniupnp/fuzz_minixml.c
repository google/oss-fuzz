// Copyright 2026 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "src/minixml.h"

/* Callback that collects element names and values */
static void xml_start_elt(void *data, const char *name, int namelen)
{
	(void)data; (void)name; (void)namelen;
}

static void xml_end_elt(void *data, const char *name, int namelen)
{
	(void)data; (void)name; (void)namelen;
}

static void xml_data(void *data, const char *d, int len)
{
	(void)data; (void)d; (void)len;
}

/* Fuzz the minixml SAX parser with arbitrary XML input. */
int LLVMFuzzerTestOneInput(const uint8_t *in, size_t insize)
{
	struct xmlparser parser;

	/* parsexml expects a null-terminated string */
	char *buf = malloc(insize + 1);
	if (!buf)
		return 0;
	memcpy(buf, in, insize);
	buf[insize] = '\0';

	memset(&parser, 0, sizeof(parser));
	parser.xmlstart = buf;
	parser.xmlsize = (int)insize;
	parser.data = NULL;
	parser.starteltfunc = xml_start_elt;
	parser.endeltfunc = xml_end_elt;
	parser.datafunc = xml_data;
	parser.attfunc = NULL;

	parsexml(&parser);

	free(buf);
	return 0;
}
