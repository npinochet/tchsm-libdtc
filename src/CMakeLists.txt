cmake_minimum_required(VERSION 2.8)

include(FindZeroMQ)
include(FindSqlite3)
include(FindJSON-C)
include(FindLibSodium)
include(FindLibConfig)
include(FindLibUUID)
include(FindTCLib)

find_package(Threads REQUIRED)

find_package(LibConfig REQUIRED)
include_directories(${CONFIG_INCLUDE_DIRS})

find_package(ZeroMQ REQUIRED)
include_directories(${ZEROMQ_INCLUDE_DIRS})

find_package(LibSodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

find_package(JSON-C REQUIRED)
include_directories(${JSON-C_INCLUDE_DIRS})

find_package(Sqlite3 REQUIRED)
include_directories(${Sqlite3_INCLUDE_DIRS})

find_package(LibUUID REQUIRED)
include_directories(${LibUUID_INCLUDE_DIRS})

find_package(TCLib REQUIRED)
include_directories(${TCLIB_INCLUDE_DIRS})

message(STATUS "TCLIB: ${TCLIB_INCLUDE_DIRS}")

set(NODE_FILES
    blocking_sql3.h
    database.c
    database.h
    err.c
    logger/logger.h
    messages.c
    messages.h
    structs.c
    structs.h
    utilities.c
    utilities.h)

set(DTC_FILES
        dtc.c
        err.c
        messages.c
        utilities.c
        structs.c)


add_library(dtc SHARED ${DTC_FILES} ${NODE_FILES})
add_executable(node node.c)


if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(PUBLIC node "-pthread")
    target_compile_options(PUBLIC dtc "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(node "${CMAKE_THREAD_LIBS_INIT}")
    target_link_libraries(dtc "${CMAKE_THREAD_LIBS_INIT}")
endif()

target_link_libraries(node ${LIBCONFIG_LIBRARIES}
                           ${ZEROMQ_LIBRARIES}
                           ${LIBSODIUM_LIBRARIES}
                           ${JSON-C_LIBRARIES}
                           ${TCLIB_LIBRARIES}
                           ${SQLITE3_LIBRARIES}
                           ${LIBUUID_LIBRARIES})

target_link_libraries(dtc ${LIBCONFIG_LIBRARIES}
                           ${ZEROMQ_LIBRARIES}
                           ${LIBSODIUM_LIBRARIES}
                           ${JSON-C_LIBRARIES}
                           ${TCLIB_LIBRARIES}
                           ${SQLITE3_LIBRARIES}
                           ${LIBUUID_LIBRARIES})

target_link_libraries(node dtc)

install(TARGETS node DESTINATION bin)
install(TARGETS dtc DESTINATION lib)
install(FILES include/dtc.h DESTINATION include)
install(FILES ../libdtc.conf DESTINATION etc)

add_subdirectory(cryptoki)
