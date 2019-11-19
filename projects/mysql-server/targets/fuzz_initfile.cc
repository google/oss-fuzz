//#include <stdint.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <string>
//#include <iostream>
//#include <mysql.h>
//#include <mysql/client_plugin.h>
//#include <mysqld_error.h>
#include "sql/sql_class.h"
#include "sql/conn_handler/channel_info.h"
#include "sql/conn_handler/connection_handler.h"
#include "sql/conn_handler/connection_handler_manager.h"
#include "sql/conn_handler/init_net_server_extension.h"
#include "sql/conn_handler/connection_handler_impl.h"
#include "sql/mysqld.h"
#include "sql/set_var.h"
#include "sql/rpl_handler.h"
#include "sql/log.h"
#include "sql/opt_costconstantcache.h"
#include "sql/sql_plugin.h"
#include "sql/sql_thd_internal_api.h"
#include "sql/mysqld_thd_manager.h"
#include "sql/bootstrap.h"
#include "mysql/psi/mysql_socket.h"
#include "mysql/psi/mysql_file.h"
#include "violite.h"
#include "util_fuzz.h"
#include <stdlib.h>
#include <libgen.h>

using namespace std;
FILE *logfile = NULL;
extern int mysqld_main(int argc, char **argv);
char *filepath = NULL;

extern "C" int LLVMFuzzerInitialize(const int* argc, char*** argv) {
    filepath = dirname(strdup((*argv)[0]));
    return 0;
}

static int bufferToFile(const char * name, const uint8_t *Data, size_t Size) {
    FILE * fd;
    if (remove(name) != 0) {
        if (errno != ENOENT) {
            printf("failed remove, errno=%d\n", errno);
            return -1;
        }
    }
    fd = fopen(name, "wb");
    if (fd == NULL) {
        printf("failed open, errno=%d\n", errno);
        return -2;
    }
    if (fwrite (Data, 1, Size, fd) != Size) {
        fclose(fd);
        return -3;
    }
    fclose(fd);
    return 0;
}

#define MAX_SIZE 256

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    if (logfile == NULL) {
        my_progname = "fuzz_initfile";
        /* first init was run with
         * mysqld --user=root --initialize-insecure --log-error-verbosity=5 --datadir=/out/mysql/data/ --basedir=/out/mysql/
         */
        utilfuzz_rmrf("/tmp/mysql_initfile");
        char command[MAX_SIZE];
        char argbase[MAX_SIZE];
        char arginitfile[MAX_SIZE];

        snprintf(command, MAX_SIZE-1, "%s/mysql/data", filepath);
        utilfuzz_cpr(command, "/tmp/mysql_initfile");

        snprintf(argbase, MAX_SIZE-1, "--basedir=%s/mysql/", filepath);
        snprintf(arginitfile, MAX_SIZE-1, "--init-file=%s/initnopw.sql", filepath);

        char *fakeargv[] = {const_cast<char *>("fuzz_initfile"),
            const_cast<char *>("--user=root"),
            const_cast<char *>("--secure-file-priv=NULL"),
            const_cast<char *>("--log-error-verbosity=5"),
            const_cast<char *>("--explicit_defaults_for_timestamp"),
            //we should adapt vio_fuzz to give a socket to openssl in order to support ssl
            const_cast<char *>("--skip-ssl"),
            const_cast<char *>("--mysqlx=0"),
            const_cast<char *>("--event-scheduler=DISABLED"),
            const_cast<char *>("--performance_schema=OFF"),
            const_cast<char *>("--thread_stack=1048576"),
            const_cast<char *>("--datadir=/tmp/mysql_initfile/"),
            const_cast<char *>("--port=3302"),
            const_cast<char *>("--socket=/tmp/initfile.sock"),
            const_cast<char *>(argbase),
            const_cast<char *>(arginitfile),
            0};
        int fakeargc = 15;
        mysqld_main(fakeargc, fakeargv);
        //terminate_compress_gtid_table_thread();

        logfile = fopen("/dev/null", "w");
    }

    bufferToFile("/tmp/initfuzz.sql", Data, Size);
    MYSQL_FILE *file;
    if (!(file =
          mysql_file_fopen(key_file_init, "/tmp/initfuzz.sql", O_RDONLY, MYF(MY_WME)))) {
        abort();
    }
    (void)bootstrap::run_bootstrap_thread("/tmp/initfuzz.sql", file, NULL, SYSTEM_THREAD_INIT_FILE);
    mysql_file_fclose(file, MYF(MY_WME));

    return 0;
}
