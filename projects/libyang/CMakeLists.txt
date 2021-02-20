cmake_minimum_required(VERSION 2.8.12)

# force out-of-source build
if(NOT FORCE_INSRC_BUILD AND ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "In-source build is not allowed. Please make a standalone build directory and run CMake from there. You may need to remove CMakeCache.txt.")
endif()

project(libyang C)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)
include(CheckSymbolExists)
include(UseCompat)

set(LIBYANG_DESCRIPTION "libyang is YANG data modelling language parser and toolkit written (and providing API) in C.")

# Correct RPATH usage on OS X
set(CMAKE_MACOSX_RPATH TRUE)

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(LIBYANG_MAJOR_VERSION 1)
set(LIBYANG_MINOR_VERSION 0)
set(LIBYANG_MICRO_VERSION 215)
set(LIBYANG_VERSION ${LIBYANG_MAJOR_VERSION}.${LIBYANG_MINOR_VERSION}.${LIBYANG_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change in libyang, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(LIBYANG_MAJOR_SOVERSION 1)
set(LIBYANG_MINOR_SOVERSION 10)
set(LIBYANG_MICRO_SOVERSION 7)
set(LIBYANG_SOVERSION_FULL ${LIBYANG_MAJOR_SOVERSION}.${LIBYANG_MINOR_SOVERSION}.${LIBYANG_MICRO_SOVERSION})
set(LIBYANG_SOVERSION ${LIBYANG_MAJOR_SOVERSION})

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -std=gnu99 -fno-strict-aliasing")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_PACKAGE "-g -O3 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -Og")

# options
if((CMAKE_BUILD_TYPE STREQUAL debug) OR (CMAKE_BUILD_TYPE STREQUAL Package))
    option(ENABLE_BUILD_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_BUILD_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_CALLGRIND_TESTS "Build performance tests to be run with callgrind" OFF)

option(ENABLE_CACHE "Enable data caching for schemas and hash tables for data (time-efficient at the cost of increased space-complexity)" ON)
option(ENABLE_LATEST_REVISIONS "Enable reusing of latest revisions of schemas" ON)
option(ENABLE_LYD_PRIV "Add a private pointer also to struct lyd_node (data node structure), just like in struct lys_node, for arbitrary user data" OFF)
option(ENABLE_FUZZ_TARGETS "Build target programs suitable for fuzzing with AFL" OFF)
set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/libyang${LIBYANG_MAJOR_SOVERSION}" CACHE STRING "Directory with libyang plugins (extensions and user types), should include major SO version")

if(ENABLE_CACHE)
    set(LY_ENABLED_CACHE 1)
endif()
if(ENABLE_LATEST_REVISIONS)
    set(LY_ENABLED_LATEST_REVISIONS 1)
endif()
if(ENABLE_LYD_PRIV)
    set(LY_ENABLED_LYD_PRIV 1)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(COMPILER_UNUSED_ATTR "UNUSED_ ## x __attribute__((__unused__))")
    set(COMPILER_PACKED_ATTR "__attribute__((__packed__))")
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # require at least clang 3.0
    if (CMAKE_C_COMPILER_VERSION VERSION_LESS 3.0)
        message(FATAL_ERROR "Clang version must be at least 3.0!")
    endif()
    set(COMPILER_UNUSED_ATTR "UNUSED_ ## x __attribute__((__unused__))")
    set(COMPILER_PACKED_ATTR "__attribute__((__packed__))")
else()
    message(WARNING "You are using an unknown compiler, it must support C11 standard \"_Generic\" statement"
        " or the \"__builtin_types_compatible_p\" built-in function.")
    set(COMPILER_UNUSED_ATTR "UNUSED_ ## x")
    set(COMPILER_PACKED_ATTR "")
endif()

include_directories(${PROJECT_BINARY_DIR}/src ${PROJECT_SOURCE_DIR}/src)
configure_file(${PROJECT_SOURCE_DIR}/src/libyang.h.in ${PROJECT_BINARY_DIR}/src/libyang.h @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/src/common.h.in ${PROJECT_BINARY_DIR}/src/common.h @ONLY)

set(EXTENSIONS_PLUGINS_DIR_MACRO "${PLUGINS_DIR}/extensions")
set(USER_TYPES_PLUGINS_DIR_MACRO "${PLUGINS_DIR}/user_types")

# setup bindings
set(GEN_LANGUAGE_BINDINGS 0 CACHE BOOL "Enable language bindings generation.")
set(GEN_CPP_BINDINGS 1 CACHE BOOL "Enable C++ bindings.")
# Python bindings depend on C++ bindings because of SWIG
set(GEN_PYTHON_BINDINGS 1 CACHE BOOL "Enable Python bindings.")
set(GEN_PYTHON_VERSION "3" CACHE STRING "Python version")
set(GEN_JAVASCRIPT_BINDINGS 0 CACHE BOOL "Enable JavaScript bindings.")
set(GEN_JAVA_BINDINGS 0 CACHE BOOL "Enable Java bindings.")

find_package(FLEX)
find_package(BISON)
find_program(SED_TOOL NAMES sed)

if(NOT BISON_FOUND)
    message(WARNING "Missing Bison.\nYou won't be able to generate source codes from changed flex/bison files.\nCompiling libyang should still works fine.")
elseif (NOT FLEX_FOUND)
    message(WARNING "Missing Flex.\nYou won't be able to generate source codes from changed flex/bison files.\nCompiling libyang should still works fine.")
else()
    if (BISON_VERSION VERSION_LESS 3)
        set(EMPTYDIR "")
    else ()
        set(EMPTYDIR "%empty")
    endif()
    configure_file(${PROJECT_SOURCE_DIR}/src/yang.y.in ${PROJECT_BINARY_DIR}/src/yang.y)
    add_custom_target(bison
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/src
        COMMAND bison -l -o parser_yang_bis.c --defines=parser_yang_bis.h ${PROJECT_BINARY_DIR}/src/yang.y
        COMMAND flex -8 -L -o parser_yang_lex.c --header-file=parser_yang_lex.h yang.l
        COMMAND ${SED_TOOL} -i 's/int yychar\;/int yychar\;\\nchar *s = NULL, *tmp_s = NULL, *ext_name = NULL\;\\nstruct lys_module *trg = NULL\;\\nstruct lys_node *tpdf_parent = NULL, *data_node = NULL\;\\nstruct lys_ext_instance_complex *ext_instance = NULL\;\\nint is_ext_instance\;\\nvoid *actual = NULL\;\\nenum yytokentype backup_type, actual_type = MODULE_KEYWORD\;\\nint64_t cnt_val = 0\;\\nint is_value = 0\;\\nvoid *yang_type = NULL\;/' parser_yang_bis.c
    )
endif()

# by default build shared library
# static build requires static libpcre library
option(ENABLE_STATIC "Build static (.a) library" OFF)

set(libsrc
    src/common.c
    src/context.c
    src/log.c
    src/hash_table.c
    src/resolve.c
    src/validation.c
    src/xml.c
    src/parser.c
    src/parser_yin.c
    src/parser_xml.c
    src/parser_json.c
    src/parser_lyb.c
    src/parser_yang_bis.c
    src/parser_yang_lex.c
    src/parser_yang.c
    src/tree_schema.c
    src/tree_data.c
    src/plugins.c
    src/printer.c
    src/xpath.c
    src/printer_yang.c
    src/printer_yin.c
    src/printer_json_schema.c
    src/printer_xml.c
    src/printer_tree.c
    src/printer_info.c
    src/printer_json.c
    src/printer_lyb.c
    src/yang_types.c)

set(lintsrc
    tools/lint/main.c
    tools/lint/main_ni.c
    tools/lint/commands.c
    tools/lint/completion.c
    tools/lint/configuration.c
    linenoise/linenoise.c)

set(resrc
    tools/re/main.c)

set(yang2yinsrc
    tools/yang2yin/main.c)

set(headers
    src/tree_schema.h
    src/tree_data.h
    src/extensions.h
    src/user_types.h
    src/xml.h
    src/dict.h)

# link compat
use_compat()

# create static libyang library
if(ENABLE_STATIC)
    add_definitions(-DSTATIC)
    set(CMAKE_EXE_LINKER_FLAGS -static)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
    set(CMAKE_EXE_LINK_DYNAMIC_C_FLAGS)       # remove -Wl,-Bdynamic
    set(CMAKE_EXE_LINK_DYNAMIC_CXX_FLAGS)
    add_library(yang STATIC ${libsrc} $<TARGET_OBJECTS:compat>)

    # switch off the tests
    if(ENABLE_BUILD_TESTS)
        message(WARNING "Tests are disabled in case of static build")
        set(ENABLE_BUILD_TESTS OFF)
        set(ENABLE_VALGRIND_TESTS OFF)
    endif(ENABLE_BUILD_TESTS)
    if(ENABLE_VALGRIND_TESTS)
        message(WARNING "Tests are disabled in case of static build")
        set(ENABLE_VALGRIND_TESTS OFF)
    endif(ENABLE_VALGRIND_TESTS)
else()
    set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
    add_library(yangobj OBJECT ${libsrc})
    add_library(yang SHARED $<TARGET_OBJECTS:yangobj> $<TARGET_OBJECTS:compat>)

    #only for tests with visible internal symbols
    add_library(yangobj_tests OBJECT ${libsrc})

    #link dl
    target_link_libraries(yang ${CMAKE_DL_LIBS})

    set_target_properties(yangobj PROPERTIES COMPILE_FLAGS "-fvisibility=hidden")
endif()

set_target_properties(yang PROPERTIES VERSION ${LIBYANG_SOVERSION_FULL} SOVERSION ${LIBYANG_SOVERSION})

# link math
target_link_libraries(yang m)

# find pthreads
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(yang ${CMAKE_THREAD_LIBS_INIT})

# find PCRE library
unset(PCRE_LIBRARY CACHE)
find_package(PCRE REQUIRED)
include_directories(${PCRE_INCLUDE_DIRS})
target_link_libraries(yang ${PCRE_LIBRARIES})

install(TARGETS yang DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${headers} ${PROJECT_BINARY_DIR}/src/libyang.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libyang)

# generate pkg-config file
configure_file("libyang.pc.in" "libyang.pc" @ONLY)
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libyang.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    # check that pkg-config includes the used path
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable pc_path pkg-config RESULT_VARIABLE RETURN OUTPUT_VARIABLE PC_PATH ERROR_QUIET)
    if(RETURN EQUAL 0)
        string(STRIP "${PC_PATH}" PC_PATH)
        set(PC_PATH "${PC_PATH}:$ENV{PKG_CONFIG_PATH}")
        string(REGEX MATCH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig" SUBSTR "${PC_PATH}")
        string(LENGTH "${SUBSTR}" SUBSTR_LEN)
        if(SUBSTR_LEN EQUAL 0)
            message(WARNING "pkg-config will not detect the new package after installation, adjust PKG_CONFIG_PATH using \"export PKG_CONFIG_PATH=\${PKG_CONFIG_PATH}:${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/pkgconfig\".")
        endif()
    endif()
endif()

# generate doxygen documentation for libyang API
find_package(Doxygen)
if(DOXYGEN_FOUND)
    find_program(DOT_PATH dot PATH_SUFFIXES graphviz2.38/bin graphviz/bin)
    if(DOT_PATH)
        set(HAVE_DOT "YES")
    else()
        set(HAVE_DOT "NO")
        message(AUTHOR_WARNING "Doxygen: to generate UML diagrams please install graphviz")
    endif()
    add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    configure_file(Doxyfile.in Doxyfile)
endif()

# clean cmake cache
add_custom_target(cclean
        COMMAND make clean
        COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -not -path './CMakeModules*' -exec rm -rf {} +
        COMMAND rm -rf Makefile Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# YANG extensions plugins
set(EXTENSIONS_LIST "nacm" "metadata" "yangdata")
# if the tests are enabled, build libyang_ext_test
if(ENABLE_BUILD_TESTS)
    find_package(CMocka 1.0.0)
    if(CMOCKA_FOUND AND CMAKE_BUILD_TYPE MATCHES debug)
        list(APPEND EXTENSIONS_LIST "libyang_ext_test")
    endif(CMOCKA_FOUND AND CMAKE_BUILD_TYPE MATCHES debug)
endif()

if(ENABLE_STATIC)
    set(EXTENSIONS_LIST_SIZE " 0 ")
    set(ITEM 0)
    foreach(EXTENSION ${EXTENSIONS_LIST})
        add_library(${EXTENSION} STATIC "src/extensions/${EXTENSION}.c")
        target_link_libraries(yang ${EXTENSION})
        set(EXTENSIONS_LIST_SIZE "${EXTENSIONS_LIST_SIZE} + lyext_size(${EXTENSION})")
        set(EXTERN_EXTENSIONS_LIST "${EXTERN_EXTENSIONS_LIST}extern struct lyext_plugin_list ${EXTENSION}[];\n")
        set(MEMCPY_EXTENSIONS_LIST "${MEMCPY_EXTENSIONS_LIST}    lyext_add(plugin, count, ${EXTENSION});\n")
        set(STATIC_LOADED_PLUGINS "${STATIC_LOADED_PLUGINS} \"${EXTENSION}\",")
        MATH(EXPR ITEM "${ITEM}+1")
    endforeach()
else()
    add_subdirectory(src/extensions)
endif(ENABLE_STATIC)

# YANG user types plugins
set(USER_TYPE_LIST "user_yang_types" "user_inet_types")
if(ENABLE_STATIC)
    set(USER_TYPE_LIST_SIZE " 0 ")
    foreach(USER_TYPE ${USER_TYPE_LIST})
        add_library(${USER_TYPE} STATIC "src/user_types/${USER_TYPE}.c")
        target_link_libraries(yang ${USER_TYPE})
        set(USER_TYPE_LIST_SIZE "${USER_TYPE_LIST_SIZE} + lytype_size(${USER_TYPE})")
        set(EXTERN_USER_TYPE_LIST "${EXTERN_USER_TYPE_LIST}extern struct lytype_plugin_list ${USER_TYPE}[];\n")
        set(MEMCPY_USER_TYPE_LIST "${MEMCPY_USER_TYPE_LIST}    lytype_add(plugin, count, ${USER_TYPE});\n")
        set(STATIC_LOADED_PLUGINS "${STATIC_LOADED_PLUGINS} \"${USER_TYPE}\",")
        MATH(EXPR ITEM "${ITEM}+1")
    endforeach()
    set(STATIC_LOADED_PLUGINS_COUNT "${ITEM}")
else()
    add_subdirectory(src/user_types)
endif()

configure_file(${PROJECT_SOURCE_DIR}/src/plugin_config.h.in ${PROJECT_BINARY_DIR}/src/plugin_config.h)

# yanglint
#add_executable(yanglint ${lintsrc} $<TARGET_OBJECTS:compat>)
#target_link_libraries(yanglint yang)
#install(TARGETS yanglint DESTINATION ${CMAKE_INSTALL_BINDIR})
#install(FILES ${PROJECT_SOURCE_DIR}/tools/lint/yanglint.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

#yangre
#add_executable(yangre ${resrc} $<TARGET_OBJECTS:compat>)
#target_link_libraries(yangre yang)
#install(TARGETS yangre DESTINATION ${CMAKE_INSTALL_BINDIR})
#install(FILES ${PROJECT_SOURCE_DIR}/tools/re/yangre.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

# yang2yin
#add_executable(yang2yin ${yang2yinsrc})

# packages
add_subdirectory(packages)

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")

if(ENABLE_VALGRIND_TESTS)
    set(ENABLE_BUILD_TESTS ON)
endif()

if(ENABLE_BUILD_TESTS)
    if(CMOCKA_FOUND)
        enable_testing()
        add_subdirectory(tests)
    else(CMOCKA_FOUND)
        message(STATUS "Disabling tests because of missing CMocka")
        set(ENABLE_BUILD_TESTS NO)
    endif(CMOCKA_FOUND)
endif()

if(ENABLE_BUILD_FUZZ_TARGETS)
    add_subdirectory(tests/fuzz)
endif()

if(GEN_LANGUAGE_BINDINGS AND GEN_CPP_BINDINGS)
    add_subdirectory(swig)
endif()
