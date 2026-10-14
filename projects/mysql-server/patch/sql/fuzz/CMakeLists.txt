IF(LIBFUZZER_COMPILE_FLAGS)
  MYSQL_ADD_EXECUTABLE(fuzz_sql_parse
    fuzz_sql_parse.cc
    LINK_LIBRARIES server_unittest_library
    SKIP_INSTALL
    )
  LIBFUZZER_ADD_TEST(fuzz_sql_parse)
ENDIF()
