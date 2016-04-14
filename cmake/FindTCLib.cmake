find_path(TCLIB_INCLUDE_DIR tc.h
        HINTS "${TCLIB_PREFIX}/include" "${CMAKE_PREFIX_PATH}/tclib/include")

find_library(TCLIB_LIBRARY NAMES libtc tc
        HINTS "${TCLIB_PREFIX}/lib" "${CMAKE_PREFIX_PATH}/tclib/lib")

set(TCLIB_INCLUDE_DIRS ${TCLIB_INCLUDE_DIR})
set(TCLIB_LIBRARIES ${TCLIB_LIBRARY})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SQLITE3_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(TCLib DEFAULT_MSG TCLIB_LIBRARY TCLIB_INCLUDE_DIR)
mark_as_advanced(TCLIB_INCLUDE_DIR TCLIB_LIBRARY)
