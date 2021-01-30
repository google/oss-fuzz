#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "burl.h"
#include "buffer.h"

void run_burl_normalize (buffer *psrc, buffer *ptmp, 
						int flags, int line, const char *in, 
						size_t in_len) {
    int qs;
    buffer_copy_string_len(psrc, in, in_len);
    qs = burl_normalize(psrc, ptmp, flags);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size <= 4) {
		return 0;
	}
	int flags = ((int*)data)[0];
	data += 4;
	size -= 4;
	char *new_str = (char *)malloc(size+1);
	if (new_str == NULL){
		return 0;
	}
	memcpy(new_str, data, size);
	new_str[size] = '\0';

    buffer *psrc = buffer_init();
    buffer *ptmp = buffer_init();
	run_burl_normalize(psrc, ptmp, flags, __LINE__, new_str, size);

    buffer_urldecode_path(psrc);
    buffer_urldecode_query(psrc);

    buffer_free(psrc);
    buffer_free(ptmp);
	free(new_str);
	return 0;     
}
