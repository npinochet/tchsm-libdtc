cmake_minimum_required(VERSION 2.8)

set(CryptographicFrontend_VERSION_MAJOR 1)
set(CryptographicFrontend_VERSION_MINOR 0)
set(MAX_SESSION_COUNT 5)
set(MIN_PIN_LEN 3)
set(MAX_PIN_LEN 10)

configure_file (
  "${PROJECT_SOURCE_DIR}/src/cryptoki/hsm/config.h.in"
  "${PROJECT_BINARY_DIR}/src/cryptoki/hsm/config.h"
  )

include_directories("${PROJECT_BINARY_DIR}/src/cryptoki/hsm")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include(FindSqlite3)
include(FindBotan)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(Boost 1.53 REQUIRED)
find_package(Sqlite3 REQUIRED)
find_package(Botan REQUIRED)
find_package(DTTCLib REQUIRED)
find_package(TCLib REQUIRED)

if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "Cannot find boost library")
endif()

if (SQLITE3_FOUND)
    include_directories(${SQLITE3_INCLUDE_DIRS})
  else()
    message(FATAL_ERROR "Cannot find sqlite3 library")
endif()

if (BOTAN_FOUND)
    include_directories(${BOTAN_INCLUDE_DIRS})
else()
    message(FATAL_ERROR "Cannot find botan library")
endif()

if (DTTCLIB_FOUND)
    include_directories(${DTTCLIB_INCLUDE_DIRS})
else ()
    message(FATAL_ERROR "Cannot find DTTCLIB")
endif()

if (TCLIB_FOUND)
    include_directories(${TCLIB_INCLUDE_DIRS})
else ()
    message(FATAL_ERROR "Cannot find TCLIB")
endif()

include_directories("cryptoki_compat")
include_directories("hsm")

set(HSM_SRC
  hsm/Database.cpp
  hsm/Database.h
  hsm/Session.cpp
  hsm/Session.h
  hsm/Slot.cpp
  hsm/Slot.h
  hsm/TcbError.cpp
  hsm/TcbError.h
  hsm/Token.cpp
  hsm/Token.h
  hsm/Configuration.cpp
  hsm/Configuration.h
  hsm/CryptoObject.cpp
  hsm/CryptoObject.h
  hsm/Application.cpp
  hsm/Application.h
  )


#message(STATUS "DTTC_LIBRARY: ${DTTCLIB_LIBRARY}")
add_library(pkcs11 SHARED pkcs11.cpp ${HSM_SRC})
target_link_libraries(pkcs11 ${DTTCLIB_LIBRARY} ${Boost_LIBRARIES} ${SQLITE3_LIBRARIES} ${BOTAN_LIBRARIES})


add_executable(pkcs11_test test.c)
target_link_libraries(pkcs11_test pkcs11 ${Boost_LIBRARIES} ${SQLITE3_LIBRARIES} ${BOTAN_LIBRARIES})

#add_executable(botanmain main.cpp)
#target_link_libraries(botanmain ${TCLIB_LIBRARY} ${BOTAN_LIBRARIES})

#set_property(TARGET botanmain PROPERTY CXX_STANDARD 11)
#set_property(TARGET botanmain PROPERTY CXX_STANDARD_REQUIRED_ON 11)
