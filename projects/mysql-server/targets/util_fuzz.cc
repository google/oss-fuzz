#include <stdio.h>
#include <ftw.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>


static int remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int rv = 2;
    if (S_ISDIR(sb->st_mode)) {
        rv = rmdir(fpath);
    } else {
        rv = remove(fpath);
    }
    printf("lol %s\n", fpath);
    return rv;
}

int utilfuzz_rmrf(char *path) {
    return nftw(path, remove_cb, 64, FTW_DEPTH | FTW_PHYS);
}

char *globalto;
size_t globallen = 0;

#define CP_NAME_MAX_SIZE 512
#define CP_BUF_SIZE 4096
static int cp_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    char newname[CP_NAME_MAX_SIZE];
    char buf[CP_BUF_SIZE];
    int rv = 2;
    snprintf(newname, CP_NAME_MAX_SIZE-1, "%s%s", globalto, fpath+globallen);
    if (FTW_D == typeflag) {
        rv = mkdir(newname, sb->st_mode);
    } else {
        int fdin = open(fpath, O_RDONLY);
        int fdout = open(newname, O_WRONLY|O_CREAT, sb->st_mode);
        int nb = read(fdin, buf, CP_BUF_SIZE);
        while (nb > 0) {
            write(fdout, buf, nb);
            nb = read(fdin, buf, CP_BUF_SIZE);
        }
        rv = 0;
    }
    return rv;
}

int utilfuzz_cpr(char *pathfrom, char *pathto) {
    globalto = pathto;
    globallen = strlen(pathfrom);
    return nftw(pathfrom, cp_cb, 64, FTW_PHYS);
}

