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
///////////////////////////////////////////////////////////////////////////

#include "config.h"
#include "augeas.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// __aug_load_module_file() is internal (internal.h has no C++ linkage guards),
// so declare it here with C linkage.
extern "C" int __aug_load_module_file(struct augeas *aug, const char *filename);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if(size==0 || size>65536){
		return 0;
	}

	// Compile the input as a lens module: drives the lexer/parser, the
	// typechecker (jmt.c) and the lens/automaton build (fa.c, lens.c).
	static char loadpath[] = "/tmp/augeas_lens_fuzz_XXXXXX";
	static char modfile[256];
	static int initialized;
	if(!initialized){
		if(mkdtemp(loadpath)==NULL){
			return 0;
		}
		snprintf(modfile, sizeof(modfile), "%s/fuzz.aug", loadpath);
		initialized = 1;
	}

	FILE *fp = fopen(modfile, "wb");
	if(fp==NULL){
		return 0;
	}
	fwrite(data, 1, size, fp);
	fclose(fp);

	struct augeas *aug = aug_init(NULL, loadpath,
		AUG_NO_LOAD|AUG_NO_STDINC|AUG_NO_MODL_AUTOLOAD|AUG_TYPE_CHECK|AUG_NO_ERR_CLOSE);
	if(aug!=NULL){
		__aug_load_module_file(aug, modfile);
		aug_close(aug);
	}

	unlink(modfile);
	return 0;
}
