/*
 * OSS-Fuzz harness for CUPS PPD (PostScript Printer Description) file parser.
 *
 * PPD files are PostScript printer configuration files parsed by CUPS when
 * installing printers. The parser handles complex keyword/value grammars with
 * a hand-written lexer that has historically contained vulnerabilities.
 */
#include <cups/cups.h>
#include <cups/ppd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Write input to a temp file so ppdOpenFile() can read it */
    char tmpname[] = "/tmp/fuzz_ppd_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) return 0;

    /* Write fuzz data */
    const uint8_t *p = data;
    size_t rem = size;
    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n <= 0) break;
        p += n;
        rem -= n;
    }
    close(fd);

    /* Parse as PPD */
    ppd_file_t *ppd = ppdOpenFile(tmpname);
    if (ppd) {
        /* Walk groups/options to exercise accessor paths */
        for (int i = 0; i < ppd->num_groups; i++) {
            ppd_group_t *group = ppd->groups + i;
            for (int j = 0; j < group->num_options; j++) {
                ppd_option_t *opt = group->options + j;
                (void)opt->keyword;
                (void)opt->text;
                for (int k = 0; k < opt->num_choices; k++) {
                    (void)opt->choices[k].choice;
                }
            }
        }
        ppdClose(ppd);
    }

    unlink(tmpname);
    return 0;
}
