cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

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
    logger/logger.c
    logger/logger.h
    messages.c
    messages.h
    structs.c
    structs.h
    utilities.c
    utilities.h)

set(MASTER_FILES
        master.c
        err.c
        logger/logger.c
        messages.c
        utilities.c
        structs.c)


add_library(dtc SHARED ${MASTER_FILES} ${NODE_FILES})
add_executable(master main.c)
add_executable(node node.c)

set_property(TARGET master PROPERTY C_STANDARD 11)
set_property(TARGET master PROPERTY C_STANDARD_REQUIRED_ON 11)


if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(PUBLIC node "-pthread")
    target_compile_options(PUBLIC dtc "-pthread")
    target_compile_options(PUBLIC master "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(node "${CMAKE_THREAD_LIBS_INIT}")
    target_link_libraries(dtc "${CMAKE_THREAD_LIBS_INIT}")
    target_link_libraries(master "${CMAKE_THREAD_LIBS_INIT}")
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

target_link_libraries(master dtc)
target_link_libraries(node dtc)

install(TARGETS node DESTINATION bin)
install(TARGETS dtc DESTINATION lib)
install(FILES include/dtc.h DESTINATION include)
install(FILES ../libdtc.conf DESTINATION etc)

add_subdirectory(cryptoki)
