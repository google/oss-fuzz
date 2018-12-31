/*****************************************************************************

gif2rgb - convert GIF to 24-bit RGB pixel triples or vice-versa

*****************************************************************************/

/***************************************************************************

Toshio Kuratomi had written this in a comment about the rgb2gif code:

  Besides fixing bugs, what's really needed is for someone to work out how to
  calculate a colormap for writing GIFs from rgb sources.  Right now, an rgb
  source that has only two colors (b/w) is being converted into an 8 bit GIF....
  Which is horrendously wasteful without compression.

I (ESR) took this off the main to-do list in 2012 because I don't think
the GIFLIB project actually needs to be in the converters-and-tools business.
Plenty of hackers do that; our job is to supply stable library capability
with our utilities mainly interesting as test tools.

***************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>

#ifdef _WIN32
#include <io.h>
#endif /* _WIN32 */

#include "gif_lib.h"

#define PROGRAM_NAME "gif2rgb"

/* ===========================================================================
 * Display error message and exit
 */
void fuzz_error(const char *msg)
{
    fprintf(stderr, "%s: %s\n", "gif2rgb_fuzzer", msg);
    exit(1);
}
/* end */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	char *inFileName = "/tmp/gif.gif";
	FILE *in = fopen(inFileName, "w");
	if(in==NULL){
		fuzz_error("failed fopen");
	}
	int Error = 0;
	if (fwrite(Data, 1, (unsigned)Size, in) != Size)
		fuzz_error("failed fwrite");
	if (fclose(in))
		fuzz_error("failed fclose");
	GifFileType *GifFile;
	GifFile = DGifOpenFileName(inFileName, &Error);
	if (GifFile == NULL){
		return 0;
	}
	DGifSlurp(GifFile);

	/*if (fclose(in))
		fuzz_error("failed fclose");*/
	EGifCloseFile(GifFile, &Error);
	return 0;
}