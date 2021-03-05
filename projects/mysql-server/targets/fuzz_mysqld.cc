//#include <stdint.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <string>
//#include <iostream>
//#include <mysql.h>
//#include <mysql/client_plugin.h>
//#include <mysqld_error.h>
#include "sql/sql_class.h"
#include "sql/protocol_classic.h"
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
#include "mysql/psi/mysql_socket.h"
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

class Channel_info_fuzz : public Channel_info {
    bool m_is_admin_conn;

    protected:
    virtual Vio *create_and_init_vio() const {
        Vio *vio = vio_new(0, VIO_TYPE_FUZZ, VIO_LOCALHOST);
        return vio;
    }

    public:
    Channel_info_fuzz(bool is_admin_conn) : m_is_admin_conn(is_admin_conn) {}

    virtual THD *create_thd() {
        Vio *vio_tmp = create_and_init_vio();
        if (vio_tmp == NULL) return NULL;

        THD *thd = new (std::nothrow) THD();
        if (thd == NULL) {
            vio_delete(vio_tmp);
            return NULL;
        }
        thd->get_protocol_classic()->init_net(vio_tmp);
        thd->set_admin_connection(m_is_admin_conn);
        init_net_server_extension(thd);
        return thd;
    }

    virtual bool is_admin_connection() const { return m_is_admin_conn; }
};

static void try_connection(Channel_info *channel_info) {
    if (my_thread_init()) {
        channel_info->send_error_and_close_channel(ER_OUT_OF_RESOURCES, 0, false);
        return;
    }

    THD *thd = channel_info->create_thd();
    if (thd == NULL) {
        channel_info->send_error_and_close_channel(ER_OUT_OF_RESOURCES, 0, false);
        return;
    }

    thd->set_new_thread_id();

    /*
     handle_one_connection() is normally the only way a thread would
     start and would always be on the very high end of the stack ,
     therefore, the thread stack always starts at the address of the
     first local variable of handle_one_connection, which is thd. We
     need to know the start of the stack so that we could check for
     stack overruns.
     */
    thd_set_thread_stack(thd, (char *)&thd);
    thd->store_globals();

    mysql_thread_set_psi_id(thd->thread_id());
    mysql_socket_set_thread_owner(
                                  thd->get_protocol_classic()->get_vio()->mysql_socket);

    Global_THD_manager *thd_manager = Global_THD_manager::get_instance();
    thd_manager->add_thd(thd);

    if (!thd_prepare_connection(thd)) {
        //authentication bypass
        abort();
    }
    delete channel_info;
    close_connection(thd, 0, false, false);
    thd->release_resources();
    thd_manager->remove_thd(thd);
    delete thd;
}


#define MAX_SIZE 256

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    if (logfile == NULL) {
        my_progname = "fuzz_mysqld";
        /* first init was run with
         * mysqld --user=root --initialize-insecure --log-error-verbosity=5 --datadir=/out/mysql/data/ --basedir=/out/mysql/
         */
        utilfuzz_rmrf("/tmp/mysqld");
        char command[MAX_SIZE];
        char argbase[MAX_SIZE];
        char arginitfile[MAX_SIZE];
        snprintf(command, MAX_SIZE-1, "%s/mysql/data", filepath);
        utilfuzz_cpr(command, "/tmp/mysqld");

        snprintf(argbase, MAX_SIZE-1, "--basedir=%s/mysql/", filepath);
        snprintf(arginitfile, MAX_SIZE-1, "--init-file=%s/init.sql", filepath);
        char *fakeargv[] = {const_cast<char *>("fuzz_mysqld"),
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
            const_cast<char *>("--datadir=/tmp/mysqld/"),
            const_cast<char *>("--port=3303"),
            const_cast<char *>("--socket=/tmp/mysqld.sock"),
            const_cast<char *>(argbase),
            const_cast<char *>(arginitfile),
            0};
        int fakeargc = 15;
        mysqld_main(fakeargc, fakeargv);
        //terminate_compress_gtid_table_thread();

        logfile = fopen("/dev/null", "w");
    }
    // The fuzzing takes place on network data received from client
    sock_initfuzz(Data,Size-1);

    Channel_info_fuzz *channel_info = new (std::nothrow) Channel_info_fuzz(Data[Size-1] & 0x80);
    try_connection(channel_info);

    return 0;
}
