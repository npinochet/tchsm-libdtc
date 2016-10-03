cmake_minimum_required(VERSION 2.8)
include (CheckFunctionExists)

find_package(Threads REQUIRED)

include(FindLibConfig)
find_package(LibConfig REQUIRED)
include_directories(${LIBCONFIG_INCLUDE_DIRS})

include(FindZeroMQ)
find_package(ZeroMQ REQUIRED)
include_directories(${ZEROMQ_INCLUDE_DIRS})

include(FindLibSodium)
find_package(LibSodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

include(FindJSON-C)
find_package(JSON-C REQUIRED)
include_directories(${JSON-C_INCLUDE_DIRS})

include(FindSqlite3)
find_package(Sqlite3 REQUIRED)
include_directories(${Sqlite3_INCLUDE_DIRS})

if(NOT APPLE)
  include(FindLibUUID)
  find_package(LibUUID REQUIRED)
  include_directories(${LibUUID_INCLUDE_DIRS})
endif()

include(FindTCLib)
find_package(TCLib REQUIRED)
include_directories(${TCLIB_INCLUDE_DIRS})

include_directories(${COMMON_INCLUDE_DIRS})

message(STATUS "TCLIB: ${TCLIB_INCLUDE_DIRS}")

set(NODE_COMMON_FILES
    blocking_sql3.h
    database.c
    database.h
    )

add_library(node_common STATIC ${NODE_COMMON_FILES})
target_link_libraries(node_common common)
set_target_properties(node_common PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(CMAKE_REQUIRED_LIBRARIES ${SQLITE3_LIBRARIES})
check_function_exists("sqlite3_unlock_notify" SQLITE3_HAVE_UNLOCK_NOTIFY)
set(CMAKE_REQUIRED_LIBRARIES)
if(NOT SQLITE3_HAVE_UNLOCK_NOTIFY)
    message(STATUS "SQLITE3 Not compiled using SQLITE_ENABLE_UNLOCK_NOTIFY")
else()
    target_compile_definitions(node_common PUBLIC SQLITE3_HAVE_UNLOCK_NOTIFY=1)
endif()


add_executable(tchsm_node node.c)


if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(tchsm_node PUBLIC "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(tchsm_node "${CMAKE_THREAD_LIBS_INIT}")
endif()

target_link_libraries(tchsm_node common
                                 node_common
                                 ${LIBCONFIG_LIBRARIES}
                                 ${ZEROMQ_LIBRARIES}
                                 ${LIBSODIUM_LIBRARIES}
                                 ${JSON-C_LIBRARIES}
                                 ${TCLIB_LIBRARIES}
                                 ${SQLITE3_LIBRARIES}
                                 ${LIBUUID_LIBRARIES})

install(TARGETS tchsm_node DESTINATION bin)
