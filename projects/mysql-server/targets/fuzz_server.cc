#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <conn_handler/connection_handler.h>
#include "violite.h"

using namespace std;
FILE *logfile = NULL;
Connection_handler * connection_handler;

class Channel_info_fuzz : public Channel_info {
    bool m_is_admin_conn;

    protected:
    virtual Vio *create_and_init_vio() const {
        Vio *vio = mysql_socket_vio_new(0, VIO_TYPE_FUZZ, 0);
        return vio;
    }

    public:
    Channel_info_fuzz(bool is_admin_conn) : m_is_admin_conn(is_admin_conn) {}

    virtual THD *create_thd() {
        THD *thd = Channel_info::create_thd();

        if (thd != NULL) {
            thd->set_admin_connection(m_is_admin_conn);
            init_net_server_extension(thd);
        }
        return thd;
    }

    virtual bool is_admin_connection() const { return m_is_admin_conn; }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }
    if (logfile == NULL) {
        connection_handler = new (std::nothrow) One_thread_connection_handler();
        logfile = fopen("/dev/null", "w");
    }
    // The fuzzing takes place on network data received from server
    sock_initfuzz(Data,Size-1);

    Channel_info_fuzz *channel_info = new (std::nothrow) Channel_info_fuzz(Data[Size-1] & 0x80);
    connection_handler->add_connection(channel_info);

    return 0;
}
