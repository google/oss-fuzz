// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>

#include "sql/sql_class.h"
#include "sql/sql_lex.h"
#include "sql/sql_parse.h"

#include "my_inttypes.h"
#include "my_rnd.h"
#include "mysql/strings/m_ctype.h"
#include "mysql_com.h"
#include "sql-common/my_decimal.h"

#include "sql/binlog.h"
#include "sql/client_settings.h"
#include "sql/conn_handler/connection_handler_manager.h"
#include "sql/dd/dd.h"
#include "sql/dd/impl/dictionary_impl.h"  // dd::Dictionary_impl
#include "sql/dd/impl/tables/column_type_elements.h"
#include "sql/dd/impl/tables/schemata.h"
#include "sql/dd/impl/tables/tables.h"
#include "sql/derror.h"
#include "sql/item_func.h"
#include "sql/keycaches.h"
#include "sql/log.h"     // query_logger
#include "sql/mysqld.h"  // set_remaining_args
#include "sql/mysqld_thd_manager.h"
#include "sql/opt_costconstantcache.h"  // optimizer cost constant cache
#include "sql/range_optimizer/range_optimizer.h"
#include "sql/rpl_filter.h"
#include "sql/rpl_handler.h"  // delegates_init()
#include "sql/set_var.h"
#include "sql/sql_class.h"
#include "sql/sql_lex.h"
#include "sql/sql_locale.h"
#include "sql/sql_plugin.h"
#include "sql/xa.h"
#include "sql/xa/transaction_cache.h"  // xa::Transaction_cache

using namespace std;

static int initialized = 0;

namespace my_testing {

class DD_initializer {
 public:
  static void SetUp();
  static void TearDown();
};

void DD_initializer::SetUp() {
  /*
    With WL#6599, Query_block::add_table_to_list() will invoke
    dd::Dictionary::is_system_view_name() method. E.g., the unit
    test InsertDelayed would invoke above API. This requires us
    to have a instance of dictionary_impl. We do not really need
    to initialize dd::System_views for this test. Also, there can
    be future test cases that need the same.
  */
  dd::Dictionary_impl::s_instance = new (std::nothrow) dd::Dictionary_impl();
  assert(dd::Dictionary_impl::s_instance != nullptr);
}

void DD_initializer::TearDown() {
  assert(dd::Dictionary_impl::s_instance != nullptr);
  delete dd::Dictionary_impl::s_instance;
}

}  // namespace my_testing

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (initialized == 0) {
        std::string my_name("fuzz_sql_parse");
        MY_INIT("fuzz_sql_parse");
        char *argv[] = {const_cast<char *>(my_name.c_str()),
                        const_cast<char *>("--secure-file-priv=NULL"),
                        const_cast<char *>("--log_syslog=0"),
                        const_cast<char *>("--explicit_defaults_for_timestamp"),
                        const_cast<char *>("--datadir=/tmp"),
                        const_cast<char *>("--lc-messages-dir=/tmp"),
                        nullptr};
        set_remaining_args(6, argv);
        system_charset_info = &my_charset_utf8mb3_general_ci;

        mysql_mutex_init(PSI_NOT_INSTRUMENTED, &LOCK_plugin, MY_MUTEX_INIT_FAST);
        sys_var_init();
        init_common_variables();
        test_flags |= TEST_SIGINT;
        test_flags |= TEST_NO_TEMP_TABLES;
        test_flags &= ~TEST_CORE_ON_SIGNAL;
        my_init_signals();
        // Install server's abort handler to better represent server environment.
        // set_my_abort(my_server_abort);
        randominit(&sql_rand, 0, 0);
        xa::Transaction_cache::initialize();
        delegates_init();
        gtid_server_init();
        // error_handler_hook = test_error_handler_hook;
        // Initialize Query_logger last, to avoid spurious warnings to stderr.
        query_logger.init();
        init_optimizer_cost_module(false);
        my_testing::DD_initializer::SetUp();

        initialized = 1;
    }

    THD *thd = new THD(false);
    THD *stack_thd = thd;

    thd->set_new_thread_id();
    thd->thread_stack = (char *)&stack_thd;
    thd->store_globals();
    lex_start(thd);
    char *db = static_cast<char *>(my_malloc(PSI_NOT_INSTRUMENTED, 3, MYF(0)));
    sprintf(db, "db");
    LEX_CSTRING db_lex_cstr = {db, strlen(db)};
    thd->reset_db(db_lex_cstr);

    Parser_state state;
    char *mutable_query = (char *)malloc(Size+1);
    if (!mutable_query) {
        return 0;
    }
    mutable_query[Size] = 0;
    memcpy(mutable_query, Data, Size);

    state.init(thd, mutable_query, Size);
    /*
      This tricks the server to parse the query and then stop,
      without executing.
    */
    thd->security_context()->set_password_expired(true);

    lex_start(thd);
    mysql_reset_thd_for_next_command(thd);
    parse_sql(thd, &state, nullptr);

    free(mutable_query);
    thd->cleanup_after_query();
    delete thd;

    return 0;
}
