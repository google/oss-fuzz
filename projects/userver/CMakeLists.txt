cmake_minimum_required(VERSION 3.12...3.31)
project(fuzzservice CXX)

# Static linking configuration - only when not fuzzing
if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(BUILD_SHARED_LIBS OFF)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(DownloadUserver)

find_package(userver COMPONENTS
    core
    QUIET
)
if(NOT userver_FOUND)
  # Tries TRY_DIR first, falls back to downloading userver from GitHub using CPM.
  download_userver(TRY_DIR third_party/userver)
endif()

userver_setup_environment()


# Common sources
include_directories(src)

add_library(${PROJECT_NAME}_objs OBJECT
    src/greeting.cpp
    src/hello.cpp
)
target_link_libraries(${PROJECT_NAME}_objs PUBLIC
  userver::core
)

# The Service
add_executable(${PROJECT_NAME} src/main.cpp)
userver_embed_file(${PROJECT_NAME}_config NAME static_config_yaml FILEPATH static_config.yaml)

if(DEFINED ENV{LIB_FUZZING_ENGINE})
  message("LIB_FUZZING_ENGINE set - $ENV{LIB_FUZZING_ENGINE}")
  target_link_libraries(${PROJECT_NAME} PRIVATE 
    ${PROJECT_NAME}_objs 
    $ENV{LIB_FUZZING_ENGINE}
    ${PROJECT_NAME}_config)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} $ENV{LIB_FUZZING_ENGINE} $ENV{LIB_HFND}")
  add_definitions(-DLIB_FUZZING_ENGINE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_objs ${PROJECT_NAME}_config)
endif()
