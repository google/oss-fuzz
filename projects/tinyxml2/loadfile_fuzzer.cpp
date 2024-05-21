#if defined( _MSC_VER )
	#if !defined( _CRT_SECURE_NO_WARNINGS )
		#define _CRT_SECURE_NO_WARNINGS		// This test file is not intended to be secure.
	#endif
#endif

#include "tinyxml2/tinyxml2.h"
#include <string>
#include <stddef.h>
#include <stdint.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#if defined( _MSC_VER ) || defined (WIN32)
	#include <crtdbg.h>
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
	_CrtMemState startMemState;
	_CrtMemState endMemState;
#else
	#include <sys/stat.h>
	#include <sys/types.h>
#endif

using namespace tinyxml2;
using namespace std;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char pathname[256];
	sprintf(pathname, "/dev/shm/fuzz-%d", getpid());
	FILE *fp = fopen(pathname, "wb");
	fwrite(data, size, 1, fp);
  	fclose(fp);
    
	XMLDocument doc;
	doc.LoadFile(pathname);

    unlink(pathname);
	return 0;
}
