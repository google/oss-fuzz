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
#include "violite.h"
#include <stdlib.h>

using namespace std;
FILE *logfile = NULL;
Connection_handler_manager * chm;
extern int mysqld_main(int argc, char **argv);

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    if (logfile == NULL) {
        my_progname = "fuzz_mysqld";
        /* first init was run with
         * mysqld --user=root --initialize-insecure --log-error-verbosity=5 --datadir=/out/mysql/data/ --basedir=/out/mysql/
         */
        system("rm -Rf /tmp/mysql");
        system("cp -r /out/mysql/data /tmp/mysql");

        char *fakeargv[] = {const_cast<char *>("fuzz_mysqld"),
            const_cast<char *>("--user=root"),
            const_cast<char *>("--secure-file-priv=NULL"),
            const_cast<char *>("--log-error-verbosity=5"),
            const_cast<char *>("--explicit_defaults_for_timestamp"),
            //we should adapt vio_fuzz to give a socket to openssl in order to support ssl
            const_cast<char *>("--skip-ssl"),
            const_cast<char *>("--mysqlx=0"),
            const_cast<char *>("--event-scheduler=DISABLED"),
            const_cast<char *>("--thread_stack=1048576"),
            const_cast<char *>("--datadir=/tmp/mysql/"),
            const_cast<char *>("--basedir=/out/mysql/"),
            const_cast<char *>("--init-file=/out/init.sql"),
            0};
        int fakeargc = 12;
        mysqld_main(fakeargc, fakeargv);

        chm = Connection_handler_manager::get_instance();
        logfile = fopen("/dev/null", "w");
    }
    // The fuzzing takes place on network data received from client
    sock_initfuzz(Data,Size-1);

    Channel_info_fuzz *channel_info = new (std::nothrow) Channel_info_fuzz(Data[Size-1] & 0x80);
    chm->process_new_connection(channel_info);

    return 0;
}
