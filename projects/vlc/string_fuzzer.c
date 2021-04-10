/* Copyright 2021 Google LLC
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void vlc_xml_decode(char *psz_value);
char *vlc_xml_encode(const char *str);
char *vlc_b64_encode_binary(const void *src, size_t length);

extern const char vlc_module_name[] = "foobar";

// vlc does not provide the implementation of strlcpy in static format
// so we declare it here
size_t strlcpy (char *tgt, const char *src, size_t bufsize)
{
    size_t length = strlen(src);

    if (bufsize > length)
        memcpy(tgt, src, length + 1);
    else
    if (bufsize > 0)
        memcpy(tgt, src, bufsize - 1), tgt[bufsize - 1] = '\0';

    return length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
	char *new_str = (char *)malloc(size+1);
	if (new_str == NULL){
	return 0;
	}
	memcpy(new_str, data, size);
	new_str[size] = '\0';
        
	char *vxe = vlc_xml_encode (new_str);
	if(vxe!=NULL)
		free(vxe);

	vlc_xml_decode(new_str);

	char *veb = vlc_b64_encode_binary(new_str, size+1);
	if(veb!=NULL) 
		free(veb);

	free(new_str);
	return 0;
}
