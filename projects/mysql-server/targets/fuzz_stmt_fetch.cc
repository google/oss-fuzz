#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <mysqld_error.h>
#include "violite.h"

using namespace std;

#define STRING_SIZE 50

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    MYSQL mysql;
    MYSQL_BIND    bind[4];
    MYSQL_RES     *prepare_meta_result;
    MYSQL_TIME    ts;
    unsigned long length[4];
    int           column_count;
    short         small_data;
    int           int_data;
    char          str_data[STRING_SIZE];
    bool          is_null[4];
    bool          error[4];
    bool opt_cleartext = true;
    unsigned int opt_ssl = SSL_MODE_DISABLED;

    mysql_init(&mysql);
    mysql_options(&mysql, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &opt_cleartext);
    mysql_options(&mysql, MYSQL_OPT_SSL_MODE, &opt_ssl);
    mysql.options.protocol = MYSQL_PROTOCOL_FUZZ;
    // The fuzzing takes place on network data received from server
    sock_initfuzz(Data,Size);
    if (!mysql_real_connect(&mysql,"localhost","root","root","",0,NULL,0))
    {
        return 0;
    }

    MYSQL_STMT *stmt = mysql_stmt_init(&mysql);
    if (!stmt)
    {
        mysql_stmt_close(stmt);
        mysql_close(&mysql);
        return 0;
    }
    if (mysql_stmt_prepare(stmt, "SELECT col1, col2, col3, col4 FROM Cars",(ulong)strlen("SELECT col1, col2, col3, col4 FROM Cars")))
    {
        mysql_stmt_close(stmt);
        mysql_close(&mysql);
        return 0;
    }
    prepare_meta_result = mysql_stmt_result_metadata(stmt);
    if (!prepare_meta_result)
    {
        mysql_stmt_close(stmt);
        mysql_close(&mysql);
        return 0;
    }

    if (mysql_stmt_execute(stmt))
    {
        mysql_stmt_close(stmt);
        mysql_close(&mysql);
        return 0;
    }
    column_count= mysql_num_fields(prepare_meta_result);
    memset(bind, 0, sizeof(bind));
    /* INTEGER COLUMN */
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= &is_null[0];
    bind[0].length= &length[0];
    bind[0].error= &error[0];

    /* STRING COLUMN */
    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    bind[1].buffer_length= STRING_SIZE;
    bind[1].is_null= &is_null[1];
    bind[1].length= &length[1];
    bind[1].error= &error[1];

    /* SMALLINT COLUMN */
    bind[2].buffer_type= MYSQL_TYPE_SHORT;
    bind[2].buffer= (char *)&small_data;
    bind[2].is_null= &is_null[2];
    bind[2].length= &length[2];
    bind[2].error= &error[2];

    /* TIMESTAMP COLUMN */
    bind[3].buffer_type= MYSQL_TYPE_TIMESTAMP;
    bind[3].buffer= (char *)&ts;
    bind[3].is_null= &is_null[3];
    bind[3].length= &length[3];
    bind[3].error= &error[3];

    if (mysql_stmt_bind_result(stmt, bind))
    {
        mysql_free_result(prepare_meta_result);
        mysql_stmt_close(stmt);
        mysql_close(&mysql);
        return 0;
    }
    if (mysql_stmt_store_result(stmt))
    {
        mysql_free_result(prepare_meta_result);
        mysql_stmt_close(stmt);
        mysql_close(&mysql);
        return 0;
    }
    while (1) {
        int status = mysql_stmt_fetch(stmt);
        if (status == 1 || status == MYSQL_NO_DATA)
            break;
    }

    mysql_free_result(prepare_meta_result);
    mysql_stmt_close(stmt);
    mysql_close(&mysql);
    return 0;
}
