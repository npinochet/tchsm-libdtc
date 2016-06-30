cmake_minimum_required(VERSION 2.8.8)
project(libdtc)

set(CMAKE_C_FLAGS_DEBUG " ${CMAKE_C_FLAGS_DEBUG} -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${libdtc_SOURCE_DIR}/cmake)

set(CMAKE_CTEST_COMMAND ctest -V)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
add_custom_target(system_test)
#TODO if?
enable_testing()

add_subdirectory(src)
add_subdirectory(tests EXCLUDE_FROM_ALL)

# make uninstall logic
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)
add_custom_target(
    uninstall COMMAND ${CMAKE_COMMAND}
                      -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
