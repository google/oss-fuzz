add_executable(shapefuzzer shapefuzzer.c)
target_compile_options(shapefuzzer PRIVATE -Wall -Wextra -Werror=format-security)
target_link_libraries(shapefuzzer mapserver_static ${LIB_FUZZING_ENGINE})

add_executable(mapfuzzer mapfuzzer.c)
target_compile_options(mapfuzzer PRIVATE -Wall -Wextra -Werror=format-security)
target_link_libraries(mapfuzzer mapserver_static ${LIB_FUZZING_ENGINE})
