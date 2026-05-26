/*
 * Fuzz harness for the tz (tzdata) TZif binary format parser.
 *
 * Target: tzloadbody() in localtime.c, which parses TZif version 1/2/3
 * binary timezone data files.
 *
 * Attack surface:
 *   - Any process calling tzset(3) with a crafted TZ environment variable
 *     pointing to an attacker-controlled file (e.g. "TZ=:./evil.tzif")
 *   - Container environments sharing a mounted /usr/share/zoneinfo
 *   - Applications that call tzalloc(3) with untrusted timezone names
 *
 * TZif format bugs that this harness can find:
 *   - Integer overflow in detzcode()/detzcode64() result usage
 *   - OOB read in ttis[], leaps[], chars[] array accesses
 *   - Sign extension issues in transition time handling
 *   - Incorrect bounds checks on ttisstdcnt/ttisutcnt/leapcnt/timecnt/typecnt/charcnt
 *   - Version-2/3 header parsing inconsistencies
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -DDONT_USE_TZDB fuzz/fuzz_tzif.c \
 *         localtime.c asctime.c difftime.c strftime.c \
 *         -o fuzz_tzif
 *
 * OSS-Fuzz:
 *   $CC $CFLAGS $LIB_FUZZING_ENGINE fuzz/fuzz_tzif.c localtime.c \
 *       asctime.c difftime.c strftime.c -o $OUT/fuzz_tzif
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Write fuzz data to a temp file, set TZ to point to it,
 * then call tzset() to trigger tzloadbody().
 * This exercises the exact production code path.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Write fuzz data to a temporary file */
    char tmppath[] = "/tmp/fuzz_tz_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0)
        return 0;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmppath);
        return 0;
    }
    close(fd);

    /* Set TZ env var to point to our file (colon prefix = absolute path) */
    char tz_env[256];
    snprintf(tz_env, sizeof(tz_env), ":%s", tmppath);
    setenv("TZ", tz_env, 1);

    /*
     * tzset() calls tzloadbody() which parses the TZif binary format.
     * With ASan/MSan, any OOB read/write or use-after-free will be caught.
     */
    tzset();

    /*
     * Also call localtime() which uses the loaded timezone state
     * to do transition lookups (exercises the binary search in transtime()).
     */
    time_t t = 0;
    localtime(&t);
    t = (time_t)1700000000; /* Nov 2023 */
    localtime(&t);

    unlink(tmppath);
    return 0;
}
