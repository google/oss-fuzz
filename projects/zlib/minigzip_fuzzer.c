/* minigzip.c -- simulate gzip using the zlib compression library
 * Copyright (C) 1995-2006, 2010, 2011, 2016 Jean-loup Gailly
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

/*
 * minigzip is a minimal implementation of the gzip utility. This is
 * only an example of using zlib and isn't meant to replace the
 * full-featured gzip. No attempt is made to deal with file systems
 * limiting names to 14 or 8+3 characters, etc... Error checking is
 * very limited. So use minigzip only for testing; use gzip for the
 * real thing.
 */

/* @(#) $Id$ */

#include "zlib.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#ifdef USE_MMAP
#  include <sys/types.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#endif

#ifndef UNALIGNED_OK
#  include <malloc.h>
#endif

#if defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
#  define snprintf _snprintf
#endif

#if !defined(Z_HAVE_UNISTD_H) && !defined(_LARGEFILE64_SOURCE)
#ifndef WIN32 /* unlink already in stdio.h for WIN32 */
  extern int unlink (const char *);
#endif
#endif

#ifndef GZ_SUFFIX
#  define GZ_SUFFIX ".gz"
#endif
#define SUFFIX_LEN (sizeof(GZ_SUFFIX)-1)

#define BUFLEN      16384        /* read buffer size */
#define BUFLENW     (BUFLEN * 3) /* write buffer size */
#define MAX_NAME_LEN 1024

#ifdef Z_SOLO
/* for Z_SOLO, create simplified gz* functions using deflate and inflate */

#if defined(Z_HAVE_UNISTD_H) || defined(Z_LARGE)
#  include <unistd.h>       /* for unlink() */
#endif

void *myalloc (void *, unsigned, unsigned);
void myfree (void *, void *);

void *myalloc(void *q, unsigned n, unsigned m)
{
    (void)q;
#ifndef UNALIGNED_OK
    return memalign(16, n * m);
#else
    return calloc(n, m);
#endif
}

void myfree(void *q, void *p)
{
    (void)q;
    free(p);
}

typedef struct gzFile_s {
    FILE *file;
    int write;
    int err;
    const char *msg;
    z_stream strm;
    unsigned char *buf;
} *gzFile;

gzFile gzopen(const char *, const char *);
gzFile gzdopen(int, const char *);
gzFile gz_open (const char *, int, const char *);

gzFile gzopen(const char *path, const char *mode)
{
    return gz_open(path, -1, mode);
}

gzFile gzdopen(int fd, const char *mode)
{
    return gz_open(NULL, fd, mode);
}

gzFile gz_open(const char *path, int fd, const char *mode)
{
    gzFile gz;
    int ret;
    int level = Z_DEFAULT_COMPRESSION;
    const char *plevel = mode;

    gz = malloc(sizeof(struct gzFile_s));
    if (gz == NULL)
        return NULL;
    gz->write = strchr(mode, 'w') != NULL;
    gz->strm.zalloc = myalloc;
    gz->strm.zfree = myfree;
    gz->strm.opaque = NULL;
    gz->buf = malloc(gz->write ? BUFLENW : BUFLEN);

    if (gz->buf == NULL) {
        free(gz);
        return NULL;
    }

    while (*plevel) {
        if (*plevel >= '0' && *plevel <= '9') {
           level = *plevel - '0';
           break;
        }
        plevel++;
    }
    if (gz->write)
        ret = deflateInit2(&(gz->strm), level, 8, 15 + 16, 8, 0);
    else {
        gz->strm.next_in = NULL;
        gz->strm.avail_in = 0;
        ret = inflateInit2(&(gz->strm), 15 + 16);
    }
    if (ret != Z_OK) {
        free(gz);
        return NULL;
    }
    gz->file = path == NULL ? fdopen(fd, gz->write ? "wb" : "rb") :
                              fopen(path, gz->write ? "wb" : "rb");
    if (gz->file == NULL) {
        gz->write ? deflateEnd(&(gz->strm)) : inflateEnd(&(gz->strm));
        free(gz);
        return NULL;
    }
    gz->err = 0;
    gz->msg = "";
    return gz;
}

int gzwrite(gzFile, const void *, unsigned);

int gzwrite(gzFile gz, const void *buf, unsigned len)
{
    z_stream *strm;

    if (gz == NULL || !gz->write)
        return 0;
    strm = &(gz->strm);
    strm->next_in = (void *)buf;
    strm->avail_in = len;
    do {
        strm->next_out = gz->buf;
        strm->avail_out = BUFLENW;
        (void)deflate(strm, Z_NO_FLUSH);
        fwrite(gz->buf, 1, BUFLENW - strm->avail_out, gz->file);
    } while (strm->avail_out == 0);
    return len;
}

int gzread(gzFile, void *, unsigned);

int gzread(gzFile gz, void *buf, unsigned len)
{
    z_stream *strm;

    if (gz == NULL || gz->write || gz->err)
        return 0;
    strm = &(gz->strm);
    strm->next_out = buf;
    strm->avail_out = len;
    do {
        if (strm->avail_in == 0)
        {
            strm->next_in = gz->buf;
            strm->avail_in = (uint32_t)fread(gz->buf, 1, BUFLEN, gz->file);
        }
        if (strm->avail_in > 0)
        {
            int ret = inflate(strm, Z_NO_FLUSH);
            if (ret == Z_DATA_ERROR) {
                gz->err = ret;
                gz->msg = strm->msg;
                return 0;
            }
            else if (ret == Z_STREAM_END)
                inflateReset(strm);
        }
        else
            break;
    } while (strm->avail_out);
    return len - strm->avail_out;
}

int gzclose(gzFile);

int gzclose(gzFile gz)
{
    z_stream *strm;

    if (gz == NULL)
        return Z_STREAM_ERROR;
    strm = &(gz->strm);
    if (gz->write) {
        strm->next_in = NULL;
        strm->avail_in = 0;
        do {
            strm->next_out = gz->buf;
            strm->avail_out = BUFLENW;
            (void)deflate(strm, Z_FINISH);
            fwrite(gz->buf, 1, BUFLENW - strm->avail_out, gz->file);
        } while (strm->avail_out == 0);
        deflateEnd(strm);
    }
    else
        inflateEnd(strm);
    free(gz->buf);
    fclose(gz->file);
    free(gz);
    return Z_OK;
}

const char *gzerror(gzFile, int *);

const char *gzerror(gzFile gz, int *err)
{
    *err = gz->err;
    return gz->msg;
}

#endif

static char *prog;

int error            (const char *msg);
int gz_compress      (FILE   *in, gzFile out);
#ifdef USE_MMAP
int  gz_compress_mmap (FILE   *in, gzFile out);
#endif
void gz_uncompress    (gzFile in, FILE   *out);
int file_compress    (char  *file, char *mode);
int file_uncompress  (char  *file);
int  main             (int argc, char *argv[]);

/* ===========================================================================
 * Display error message and return
 */
int error(const char *msg)
{
    fprintf(stderr, "%s: %s\n", prog, msg);
    return 0;
}

/* ===========================================================================
 * Compress input to output then close both files.
 */

int gz_compress(FILE   *in, gzFile out)
{
    char buf[BUFLEN];
    int len;
    int err;

#ifdef USE_MMAP
    /* Try first compressing with mmap. If mmap fails (minigzip used in a
     * pipe), use the normal fread loop.
     */
    if (gz_compress_mmap(in, out) == Z_OK) return;
#endif
    /* Clear out the contents of buf before reading from the file to avoid
       MemorySanitizer: use-of-uninitialized-value warnings. */
    memset(buf, 0, sizeof(buf));
    for (;;) {
        len = (int)fread(buf, 1, sizeof(buf), in);
        if (ferror(in)) {
            perror("fread");
            return 0;
        }
        if (len == 0) break;

        if (gzwrite(out, buf, (unsigned)len) != len) error(gzerror(out, &err));
    }
    fclose(in);
    if (gzclose(out) != Z_OK) error("failed gzclose");
    return 0;
}

#ifdef USE_MMAP /* MMAP version, Miguel Albrecht <malbrech@eso.org> */

/* Try compressing the input file at once using mmap. Return Z_OK if
 * if success, Z_ERRNO otherwise.
 */
int gz_compress_mmap(FILE   *in, gzFile out)
{
    int len;
    int err;
    int ifd = fileno(in);
    caddr_t buf;    /* mmap'ed buffer for the entire input file */
    off_t buf_len;  /* length of the input file */
    struct stat sb;

    /* Determine the size of the file, needed for mmap: */
    if (fstat(ifd, &sb) < 0) return Z_ERRNO;
    buf_len = sb.st_size;
    if (buf_len <= 0) return Z_ERRNO;

    /* Now do the actual mmap: */
    buf = mmap((caddr_t) 0, buf_len, PROT_READ, MAP_SHARED, ifd, (off_t)0);
    if (buf == (caddr_t)(-1)) return Z_ERRNO;

    /* Compress the whole file at once: */
    len = gzwrite(out, (char *)buf, (unsigned)buf_len);

    if (len != (int)buf_len) error(gzerror(out, &err));

    munmap(buf, buf_len);
    fclose(in);
    if (gzclose(out) != Z_OK) error("failed gzclose");
    return Z_OK;
}
#endif /* USE_MMAP */

/* ===========================================================================
 * Uncompress input to output then close both files.
 */
void gz_uncompress(gzFile in, FILE   *out)
{
    char buf[BUFLENW];
    int len;
    int err;

    for (;;) {
        len = gzread(in, buf, sizeof(buf));
        if (len < 0) error (gzerror(in, &err));
        if (len == 0) break;

        if ((int)fwrite(buf, 1, (unsigned)len, out) != len) {
            error("failed fwrite");
        }
    }
    if (fclose(out)) error("failed fclose");

    if (gzclose(in) != Z_OK) error("failed gzclose");
}


/* ===========================================================================
 * Compress the given file: create a corresponding .gz file and remove the
 * original.
 */
int file_compress(char  *file, char  *mode)
{
    char outfile[MAX_NAME_LEN];
    FILE  *in;
    gzFile out;

    if (strlen(file) + strlen(GZ_SUFFIX) >= sizeof(outfile)) {
        fprintf(stderr, "%s: filename too long\n", prog);
        return 0;
    }

    snprintf(outfile, sizeof(outfile), "%s%s", file, GZ_SUFFIX);

    in = fopen(file, "rb");
    if (in == NULL) {
        perror(file);
        return 0;
    }
    out = gzopen(outfile, mode);
    if (out == NULL) {
        fprintf(stderr, "%s: can't gzopen %s\n", prog, outfile);
        return 0;
    }
    gz_compress(in, out);

    unlink(file);
    return 0;
}


/* ===========================================================================
 * Uncompress the given file and remove the original.
 */
int file_uncompress(char  *file)
{
    char buf[MAX_NAME_LEN];
    char *infile, *outfile;
    FILE  *out;
    gzFile in;
    size_t len = strlen(file);

    if (len + strlen(GZ_SUFFIX) >= sizeof(buf)) {
        fprintf(stderr, "%s: filename too long\n", prog);
        return 0;
    }

    snprintf(buf, sizeof(buf), "%s", file);

    if (len > SUFFIX_LEN && strcmp(file+len-SUFFIX_LEN, GZ_SUFFIX) == 0) {
        infile = file;
        outfile = buf;
        outfile[len-3] = '\0';
    } else {
        outfile = file;
        infile = buf;
        snprintf(buf + len, sizeof(buf) - len, "%s", GZ_SUFFIX);
    }
    in = gzopen(infile, "rb");
    if (in == NULL) {
        fprintf(stderr, "%s: can't gzopen %s\n", prog, infile);
        return 0;
    }
    out = fopen(outfile, "wb");
    if (out == NULL) {
        perror(file);
        return 0;
    }

    gz_uncompress(in, out);

    unlink(infile);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {
  char *inFileName = "/tmp/minigzip_fuzzer.out";
  char *outFileName = "/tmp/minigzip_fuzzer.out.gz";
  char outmode[20];
  FILE *in;
  char buf[BUFLEN];
  uint32_t offset = 0;

  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;
  if (dataLen < 1 || dataLen > kMaxSize)
    return 0;

  in = fopen(inFileName, "w");
  if (fwrite(data, 1, (unsigned)dataLen, in) != dataLen)
    error("failed fwrite");
  if (fclose(in))
    error("failed fclose");

  memset(outmode, 0, sizeof(outmode));
  snprintf(outmode, sizeof(outmode), "%s", "wb");

  /* Compression level: [0..9]. */
  outmode[2] = data[0] % 10;

  switch (data[0] % 4) {
  default:
  case 0:
    outmode[3] = 0;
    break;
  case 1:
    /* compress with Z_FILTERED */
    outmode[3] = 'f';
    break;
  case 2:
    /* compress with Z_HUFFMAN_ONLY */
    outmode[3] = 'h';
    break;
  case 3:
    /* compress with Z_RLE */
    outmode[3] = 'R';
    break;
  }

  file_compress(inFileName, outmode);
  file_uncompress(outFileName);

  /* Check that the uncompressed file matches the input data. */
  in = fopen(inFileName, "rb");
  if (in == NULL) {
    perror(inFileName);
    return 0;
  }

  memset(buf, 0, sizeof(buf));
  for (;;) {
    int len = (int)fread(buf, 1, sizeof(buf), in);
    if (ferror(in)) {
      perror("fread");
      return 0;
    }
    if (len == 0)
      break;
    assert(0 == memcmp(data + offset, buf, len));
    offset += len;
  }

  if (fclose(in))
    error("failed fclose");

  /* This function must return 0. */
  return 0;
}
