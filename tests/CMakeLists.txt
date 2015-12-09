cmake_minimum_required(VERSION 2.8)

find_package(TCLib REQUIRED)
include_directories(${TCLIB_INCLUDE_DIRS})

find_package(CHECK REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})

set(tests
        structs_test
        messages_test
        database_test
)

foreach(test ${tests})
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} ${CHECK_LIBRARIES} dt_tc  m rt)

    add_test(NAME ${test} COMMAND ${test})

    add_dependencies(check ${test})

endforeach()
