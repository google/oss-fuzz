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
FILE *logfile = NULL;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    MYSQL mysql;
    long flags;
    bool opt_cleartext = true;
    unsigned int opt_ssl = SSL_MODE_DISABLED;
    MYSQL_RES *result;

    if (Size < sizeof(unsigned long)) {
        return 0;
    }
    if (logfile == NULL) {
        logfile = fopen("/dev/null", "w");
    }
    memcpy(&flags, Data + Size - sizeof(unsigned long), sizeof(unsigned long));
    mysql_init(&mysql);
    mysql_options(&mysql, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &opt_cleartext);
    mysql_options(&mysql, MYSQL_OPT_SSL_MODE, &opt_ssl);
    mysql.options.protocol = MYSQL_PROTOCOL_FUZZ;
    // The fuzzing takes place on network data received from server
    sock_initfuzz(Data,Size - sizeof(unsigned long));
    if (!mysql_real_connect(&mysql, "localhost", "root", "root", "dbname", 0, NULL, flags)) {
        goto out;
    } else {
        fprintf(logfile, "The last inserted row id is: %llu\n", mysql_insert_id(&mysql));
        fprintf(logfile, "%llu affected rows\n", mysql_affected_rows(&mysql));
        mysql_info(&mysql);
    }

    mysql_query(&mysql, "CREATE DATABASE fuzzbase");
    if (mysql_query(&mysql, "SELECT * FROM CARS")) {
        goto out;
    }
    result = mysql_store_result(&mysql);
    if (result != NULL) {
        int num_fields = mysql_num_fields(result);
        MYSQL_FIELD *field;
        while((field = mysql_fetch_field(result))) {
            fprintf(logfile, "%s\n", field->name);
        }
        MYSQL_ROW row = mysql_fetch_row(result);
        unsigned long * lengths = mysql_fetch_lengths(result);
        while (row ) {
            for(int i = 0; i < num_fields; i++) {
                fprintf(logfile, "length %lu, %s\n", lengths[i], row[i] ? row[i] : "NULL");
            }
            row = mysql_fetch_row(result);
        }
        mysql_free_result(result);
    }
    result = mysql_list_dbs(&mysql, NULL);
    if (result) {
        mysql_free_result(result);
    }
    result = mysql_list_tables(&mysql, NULL);
    if (result) {
        mysql_free_result(result);
    }
    result = mysql_list_fields(&mysql, "sometable", NULL);
    if (result) {
        mysql_free_result(result);
    }
    result = mysql_list_processes(&mysql);
    if (result) {
        mysql_free_result(result);
    }
    mysql_ping(&mysql);

    if (mysql_change_user(&mysql, "user", "password", "new_database")) {
        goto out;
    }
    if (mysql_query(&mysql, "INSERT INTO Fuzzers(Name) VALUES('myfuzzer')") == 0) {
        fprintf(logfile, "The last inserted row id is: %llu\n", mysql_insert_id(&mysql));
        fprintf(logfile, "%llu affected rows\n", mysql_affected_rows(&mysql));
        mysql_info(&mysql);
    }
    mysql_get_host_info(&mysql);
    mysql_get_proto_info(&mysql);
    mysql_get_server_info(&mysql);
    mysql_get_server_version(&mysql);
    mysql_dump_debug_info(&mysql);
    mysql_sqlstate(&mysql);
    mysql_stat(&mysql);

out:
    mysql_close(&mysql);
    return 0;
}
