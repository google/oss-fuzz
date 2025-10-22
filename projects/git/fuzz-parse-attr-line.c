/* Copyright 2024 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
	  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "git-compat-util.h"
#include "attr.h"

struct attr_state {
	const struct git_attr *attr;
	const char *setto;
};

struct pattern {
	const char *pattern;
	int patternlen;
	int nowildcardlen;
	unsigned flags;		/* PATTERN_FLAG_* */
};

struct match_attr {
	union {
		struct pattern pat;
		const struct git_attr *attr;
	} u;
	char is_macro;
	size_t num_attr;
	struct attr_state state[FLEX_ARRAY];
};

struct match_attr *parse_attr_line(const char *line, const char *src,
					  int lineno, unsigned flags);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct match_attr *res;
	char *buf;

	buf = malloc(size + 1);
	if (!buf)
		return 0;

	memcpy(buf, data, size);
	buf[size] = 0;

	res = parse_attr_line(buf, "/tmp/test/", 0, 0);

	if (res) {
		int j;
		for (j = 0; j < res->num_attr; j++) {
			const char *setto = res->state[j].setto;
			if (ATTR_TRUE(setto) || ATTR_FALSE(setto) ||
				ATTR_UNSET(setto))
				;
			else
				free((char *)setto);
		}
		free(res);
	}
	free(buf);

	return 0;
}
