cmake_minimum_required(VERSION 2.8)
project(distributed_tclib C)

set(CMAKE_CTEST_COMMAND ctest -V)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
#TODO if?
enable_testing()

add_subdirectory(src)
add_subdirectory(tests EXCLUDE_FROM_ALL)
