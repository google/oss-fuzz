if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
  MYSQL_ADD_EXECUTABLE(fuzz_real_query fuzz_real_query.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_real_query mysqlclient)

  MYSQL_ADD_EXECUTABLE(fuzz_stmt_fetch fuzz_stmt_fetch.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_stmt_fetch mysqlclient)

  MYSQL_ADD_EXECUTABLE(fuzz_mysqld fuzz_mysqld.cc util_fuzz.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_mysqld sql_main sql_gis binlog rpl master slave sql_dd mysys minchassis binlogevents_static ${ICU_LIBRARIES})

  MYSQL_ADD_EXECUTABLE(fuzz_initfile fuzz_initfile.cc util_fuzz.cc onefile.cc)
  TARGET_LINK_LIBRARIES(fuzz_initfile sql_main sql_gis binlog rpl master slave sql_dd mysys minchassis binlogevents_static ${ICU_LIBRARIES})
else()
  MYSQL_ADD_EXECUTABLE(fuzz_real_query fuzz_real_query.cc)
  TARGET_LINK_LIBRARIES(fuzz_real_query mysqlclient)
  TARGET_LINK_LIBRARIES(fuzz_real_query $ENV{LIB_FUZZING_ENGINE})

  MYSQL_ADD_EXECUTABLE(fuzz_stmt_fetch fuzz_stmt_fetch.cc)
  TARGET_LINK_LIBRARIES(fuzz_stmt_fetch mysqlclient)
  TARGET_LINK_LIBRARIES(fuzz_stmt_fetch $ENV{LIB_FUZZING_ENGINE})

  MYSQL_ADD_EXECUTABLE(fuzz_mysqld fuzz_mysqld.cc util_fuzz.cc)
  TARGET_LINK_LIBRARIES(fuzz_mysqld sql_main sql_gis binlog rpl master slave sql_dd mysys minchassis binlogevents_static ${ICU_LIBRARIES})
  TARGET_LINK_LIBRARIES(fuzz_mysqld $ENV{LIB_FUZZING_ENGINE})

  MYSQL_ADD_EXECUTABLE(fuzz_initfile fuzz_initfile.cc util_fuzz.cc)
  TARGET_LINK_LIBRARIES(fuzz_initfile sql_main sql_gis binlog rpl master slave sql_dd mysys minchassis binlogevents_static ${ICU_LIBRARIES})
  TARGET_LINK_LIBRARIES(fuzz_initfile $ENV{LIB_FUZZING_ENGINE})
endif()
