find_library(FUZZINGENGINE_LIB FuzzingEngine)

if(NOT FUZZINGENGINE_LIB)
  MYSQL_ADD_EXECUTABLE(fuzz_real_query fuzz_real_query.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_real_query mysqlclient)

  MYSQL_ADD_EXECUTABLE(fuzz_stmt_fetch fuzz_stmt_fetch.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_stmt_fetch mysqlclient)

  MYSQL_ADD_EXECUTABLE(fuzz_mysqld fuzz_mysqld.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_mysqld sql_main sql_gis binlog rpl master slave sql_main sql_dd sql_gis mysys mysys_ssl binlogevents_static ${ICU_LIBRARIES})
else()
  MYSQL_ADD_EXECUTABLE(fuzz_real_query fuzz_real_query.cc)
  TARGET_LINK_LIBRARIES(fuzz_real_query mysqlclient)
  TARGET_LINK_LIBRARIES(fuzz_real_query FuzzingEngine)

  MYSQL_ADD_EXECUTABLE(fuzz_stmt_fetch fuzz_stmt_fetch.cc)
  TARGET_LINK_LIBRARIES(fuzz_stmt_fetch mysqlclient)
  TARGET_LINK_LIBRARIES(fuzz_stmt_fetch FuzzingEngine)

  MYSQL_ADD_EXECUTABLE(fuzz_mysqld fuzz_mysqld.cc)
  TARGET_LINK_LIBRARIES(fuzz_mysqld sql_main sql_gis binlog rpl master slave sql_main sql_dd sql_gis mysys mysys_ssl binlogevents_static ${ICU_LIBRARIES})
  TARGET_LINK_LIBRARIES(fuzz_mysqld FuzzingEngine)
endif()
