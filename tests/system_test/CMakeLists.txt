cmake_minimum_required(VERSION 2.8)

include(FindBotan)
find_package(Botan 1.10 REQUIRED)
include_directories(${BOTAN_INCLUDE_DIRS})


find_package(TCLib REQUIRED)
include_directories(${TCLIB_INCLUDE_DIRS})
include_directories(${PROJECT_BINARY_DIR})
include_directories(${libdtc_SOURCE_DIR}/src/)
include_directories(${libdtc_SOURCE_DIR}/src/cryptoki/cryptoki_compat/)

add_executable(dtc_master_test dtc_master_test.c)
add_executable(pkcs_11_test pkcs_11_test.c)

target_link_libraries(dtc_master_test dtc ${BOTAN_LIBRARIES})
target_link_libraries(pkcs_11_test pkcs11 ${BOTAN_LIBRARIES})

add_dependencies(system_test dtc_master_test
                             pkcs_11_test
                             tchsm_node)
