
# CHECK_FOUND - true if library and headers were found
# CHECK_INCLUDE_DIRS - include directories
# CHECK_LIBRARIES - library directories

if(CHECK_INCLUDE_DIRS AND CHECK_LIBRARTY)
    set(CHECK_FOUND TRUE)
else()
    find_package(PkgConfig)
    pkg_check_modules(PC_CHECK QUIET check)

    find_path(CHECK_INCLUDE_DIR check.h
        HINTS ${CMAKE_INSTALL_PREFIX}/include ${PC_CHECK_INCLUDEDIR} ${PC_CHECK_INCLUDE_DIRS} PATH_SUFFIXES check)

    find_library(CHECK_LIBRARY NAMES check
        HINTS ${CMAKE_INSTALL_PREFIX}/lib ${PC_CHECK_LIBDIR} ${PC_CHECK_LIBRARY_DIRS})

    set(CHECK_LIBRARIES ${CHECK_LIBRARY})
    set(CHECK_INCLUDE_DIRS ${CHECK_INCLUDE_DIR})

    include(FindPackageHandleStandardArgs)

    find_package_handle_standard_args(CHECK DEFAULT_MSG CHECK_LIBRARY CHECK_INCLUDE_DIR)

    mark_as_advanced(CHECK_INCLUDE_DIR CHECK_LIBRARY)

endif()
