find_path(DTTCLIB_INCLUDE_DIR dtc.h
        HINTS "${DTTCLIB_PREFIX}/include" "${CMAKE_PREFIX_PATH}/dtc/include")

find_library(DTTCLIB_LIBRARY NAMES libdt_tc.so
        HINTS "${DTTCLIB_PREFIX}/lib" "${CMAKE_PREFIX_PATH}/dtc/lib")

    set(DTTCLIB_INCLUDE_DIRS ${DTTCLIB_INCLUDE_DIR})
    set(DTTCLIB_LIBRARIES ${DTTCLIB_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SQLITE3_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(DTTCLIB DEFAULT_MSG DTTCLIB_LIBRARY DTTCLIB_INCLUDE_DIR)
mark_as_advanced(DTTCLIB_INCLUDE_DIR DTTCLIB_LIBRARY)
