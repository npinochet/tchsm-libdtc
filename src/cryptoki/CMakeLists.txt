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
include_directories("${PROJECT_SOURCE_DIR}/src/include")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(${CONFIG_INCLUDE_DIRS})

find_package(LibConfig REQUIRED)
include_directories(${LIBCONFIG_INCLUDE_DIRS})

if (NOT APPLE)
  include(FindLibUUID)
  find_package(LibUUID REQUIRED)
  include_directories(${LibUUID_INCLUDE_DIRS})
endif()

find_package(Sqlite3 REQUIRED)
include_directories(${SQLITE3_INCLUDE_DIRS})

include(FindBotan)
find_package(Botan 1.10 REQUIRED)
include_directories(${BOTAN_INCLUDE_DIRS})

find_package(TCLib REQUIRED)
include_directories(${TCLIB_INCLUDE_DIRS})
    
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
  hsm/Mutex.cpp
  hsm/Mutex.h
  hsm/OSMutex.cpp
  hsm/OSMutex.h
  )


add_library(pkcs11 SHARED pkcs11.cpp ${HSM_SRC})
target_link_libraries(pkcs11 dtc ${SQLITE3_LIBRARIES} ${BOTAN_LIBRARIES} ${LIBCONFIG_LIBRARIES} ${LIBUUID_LIBRARIES})

install(TARGETS pkcs11 DESTINATION lib)
install(FILES ./cryptoki.conf DESTINATION etc)
