cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
SET(BUILD_SHARED_LIBRARIES OFF)
SET(CMAKE_EXE_LINKER_FLAGS "-static")

find_package(Threads REQUIRED)

find_package(CONFIG REQUIRED)
include_directories(${CONFIG_INCLUDE_DIRS})

find_package(ZMQ REQUIRED)
include_directories(${ZMQ_INCLUDE_DIRS})

find_package(SODIUM)
include_directories(${SODIUM_INCLUDE_DIRS})

find_package(JSONC REQUIRED)
include_directories(${JSONC_INCLUDE_DIRS})

find_package(TCLIB REQUIRED)
include_directories(${TCLIB_INCLUDE_DIRS})

find_package(Sqlite3 REQUIRED)
include_directories(${Sqlite3_INCLUDE_DIRS})

set(NODE_FILES
    blocking_sql3.h
    database.c
    database.h
    err.c
    err.h
    logger/logger.c
    logger/logger.h
    messages.c
    messages.h
    structs.c
    structs.h
    utilities.c
    utilities.h)


add_executable(node node.c ${NODE_FILES})

set_target_properties(node PROPERTIES LINKER_LANGUAGE CXX)

if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(PUBLIC node "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
    target_link_libraries(node "${CMAKE_THREAD_LIBS_INIT}")
endif()

target_link_libraries(node ${CONFIG_LIBRARIES}
                           ${ZMQ_LIBRARIES}
                           ${SODIUM_LIBRARIES}
                           ${JSONC_LIBRARIES}
                           ${TCLIB_LIBRARIES}
                           ${Sqlite3_LIBRARIES})
