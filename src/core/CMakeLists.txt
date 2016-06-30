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
include_directories("../include")

message(STATUS "TCLIB: ${TCLIB_INCLUDE_DIRS}")

set(COMMON_FILES
        err.c
        messages.c
        include/messages.h
        utilities.c
        include/utilities.h
        structs.c
        include/structs.h)

set(DTC_FILES
        dtc.c)

add_library(common STATIC ${COMMON_FILES})
set_target_properties(common PROPERTIES POSITION_INDEPENDENT_CODE ON)
add_library(dtc_obj OBJECT ${DTC_FILES})
set_target_properties(dtc_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(dtc_obj PUBLIC include)

target_link_libraries(common ${LIBCONFIG_LIBRARIES}
                             ${LIBUUID_LIBRARIES}
                             ${ZEROMQ_LIBRARIES})

add_library(dtc SHARED $<TARGET_OBJECTS:dtc_obj>)
add_library(dtc_static STATIC $<TARGET_OBJECTS:dtc_obj>)
set_target_properties(dtc_static PROPERTIES OUTPUT_NAME dtc)
if(THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(dtc PUBLIC "-pthread")
    target_compile_options(dtc_static PUBLIC "-pthread")
endif()
if(${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(dtc "${CMAKE_THREAD_LIBS_INIT}")
    target_link_libraries(dtc_static "${CMAKE_THREAD_LIBS_INIT}")
endif()

set(dtc_dependencies ${JSON-C_LIBRARIES}
                     ${LIBCONFIG_LIBRARIES}
                     ${LIBSODIUM_LIBRARIES}
                     ${SQLITE3_LIBRARIES}
                     ${TCLIB_LIBRARIES}
                     ${ZEROMQ_LIBRARIES})

target_link_libraries(dtc common ${dtc_dependencies})
target_link_libraries(dtc_static common ${dtc_dependencies})

target_include_directories(common PUBLIC include ../include)
target_include_directories(dtc PUBLIC ../include)
target_include_directories(dtc_static PUBLIC ../include)

install(TARGETS dtc DESTINATION lib)
install(TARGETS dtc_static DESTINATION lib)
