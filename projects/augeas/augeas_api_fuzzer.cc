#include "config.h"
#include "augeas.h"
#include "internal.h"
#include "memory.h"
#include "syntax.h"
#include "transform.h"
#include "errcode.h"


#include <fnmatch.h>
#include <argz.h>
#include <string.h>
#include <stdarg.h>
#include <locale.h>



extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if(size<3){
		return 0;
	}
	
	char *loadpath = NULL;
	const char *value;
	const char *label;
	char *new_str = (char *)malloc(size+1);
	if (new_str == NULL){
		return 0;
	}
	memcpy(new_str, data, size);
	new_str[size] = '\0';
	
	struct augeas *aug = aug_init(new_str, loadpath, AUG_NO_STDINC|AUG_NO_LOAD);
	aug_defvar(aug, new_str, &new_str[1]);
	aug_get(aug, new_str, &value);
	aug_label(aug, new_str, &label);
	
	aug_rename(aug, new_str, &new_str[1]);
	aug_text_store(aug, &new_str[1], new_str, &new_str[2]);	
	aug_print(aug, stdout, new_str);
	aug_setm(aug, new_str, NULL, &new_str[1]);	
	
	free(new_str);
	aug_close(aug);
	return 0;
}
