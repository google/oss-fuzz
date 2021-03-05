/* Copyright 2020 Google Inc.

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
#include "sql/sql_parse.h"
#include "mysql/psi/mysql_socket.h"
#include "violite.h"
#include "util_fuzz.h"
#include <stdlib.h>
#include <libgen.h>

using namespace std;
FILE *logfile = NULL;
Connection_handler_manager * chm;
extern int mysqld_main(int argc, char **argv);
char *filepath = NULL;

extern "C" int LLVMFuzzerInitialize(const int* argc, char*** argv) {
    filepath = dirname(strdup((*argv)[0]));
    return 0;
}


// FIXME: Fix this buffer with succesful authenticated connection for mysql 8.21.
const uint8_t startConn[] =
"\xa6\x00\x00\x01\x85\xa6\xff\x01\x00\x00\x00\x01\x2d\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x72\x6f\x6f\x74\x00\x01\x00\x6d\x79\x73\x71\x6c" \
"\x5f\x63\x6c\x65\x61\x72\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00" \
"\x69\x04\x5f\x70\x69\x64\x05\x35\x34\x30\x30\x31\x03\x5f\x6f\x73" \
"\x08\x6f\x73\x78\x31\x30\x2e\x31\x33\x09\x5f\x70\x6c\x61\x74\x66" \
"\x6f\x72\x6d\x06\x78\x38\x36\x5f\x36\x34\x0f\x5f\x63\x6c\x69\x65" \
"\x6e\x74\x5f\x76\x65\x72\x73\x69\x6f\x6e\x06\x38\x2e\x30\x2e\x31" \
"\x36\x0c\x5f\x63\x6c\x69\x65\x6e\x74\x5f\x6e\x61\x6d\x65\x08\x6c" \
"\x69\x62\x6d\x79\x73\x71\x6c\x0c\x70\x72\x6f\x67\x72\x61\x6d\x5f" \
"\x6e\x61\x6d\x65\x05\x6d\x79\x73\x71\x6c"
"\x00\x00\x00\x03"
;


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

#define MAX_SIZE 256


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    if (logfile == NULL) {
        my_progname = "fuzz_docommand";
        /* first init was run with
         * mysqld --user=root --initialize-insecure --log-error-verbosity=5 --datadir=/out/mysql/data/ --basedir=/out/mysql/
         */
        utilfuzz_rmrf("/tmp/mysql_docommand");
        char command[MAX_SIZE];
        char argbase[MAX_SIZE];
        char arginitfile[MAX_SIZE];
        snprintf(command, MAX_SIZE-1, "%s/mysql/data", filepath);
        utilfuzz_cpr(command, "/tmp/mysql_docommand");

        snprintf(argbase, MAX_SIZE-1, "--basedir=%s/mysql/", filepath);
        snprintf(arginitfile, MAX_SIZE-1, "--init-file=%s/initnopw.sql", filepath);

        char *fakeargv[] = {const_cast<char *>("fuzz_docommand"),
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
            const_cast<char *>("--datadir=/tmp/mysql_docommand/"),
            const_cast<char *>("--port=3301"),
            const_cast<char *>("--socket=/tmp/docommand.sock"),
            const_cast<char *>(argbase),
            const_cast<char *>(arginitfile),
            0};
        int fakeargc = 15;
        mysqld_main(fakeargc, fakeargv);

        chm = Connection_handler_manager::get_instance();
        logfile = fopen("/dev/null", "w");
    }
    Channel_info_fuzz * channel_info = new (std::nothrow) Channel_info_fuzz(true);
    sock_initfuzz(startConn,sizeof(startConn));
    if (my_thread_init()) {
        channel_info->send_error_and_close_channel(ER_OUT_OF_RESOURCES, 0, false);
        abort();
    }

    THD *thd_fuzz = channel_info->create_thd();
    if (thd_fuzz == NULL) {
        channel_info->send_error_and_close_channel(ER_OUT_OF_RESOURCES, 0, false);
        abort();
    }

    thd_fuzz->set_new_thread_id();
    thd_set_thread_stack(thd_fuzz, (char *)&thd_fuzz);
    thd_fuzz->store_globals();
    mysql_thread_set_psi_id(thd_fuzz->thread_id());
    mysql_socket_set_thread_owner(
                                  thd_fuzz->get_protocol_classic()->get_vio()->mysql_socket);
    Global_THD_manager *thd_manager = Global_THD_manager::get_instance();
    thd_manager->add_thd(thd_fuzz);
    if (thd_prepare_connection(thd_fuzz)) {
        abort();
    }
    delete channel_info;

    // The fuzzing takes place on network data received from client
    sock_initfuzz(Data,Size);

    while (thd_connection_alive(thd_fuzz)) {
        if (do_command(thd_fuzz)) break;
    }
    end_connection(thd_fuzz);
    close_connection(thd_fuzz, 0, false, false);
    thd_fuzz->release_resources();
    thd_manager->remove_thd(thd_fuzz);
    delete thd_fuzz;

    return 0;
}
