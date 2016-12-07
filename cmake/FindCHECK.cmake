
# CHECK_FOUND - true if library and headers were found
# CHECK_INCLUDE_DIRS - include directories
# CHECK_LIBRARIES - library directories

if(CHECK_INCLUDE_DIRS AND CHECK_LIBRARY)
    set(CHECK_FOUND TRUE)
else()
    find_package(PkgConfig)
    pkg_check_modules(CHECK QUIET check)

    find_path(CHECK_INCLUDE_DIR check.h
        HINTS ${CMAKE_INSTALL_PREFIX}/include ${CHECK_INCLUDEDIR} ${CHECK_INCLUDE_DIRS} PATH_SUFFIXES check)

    find_library(CHECK_LIBRARY NAMES check
        HINTS ${CMAKE_INSTALL_PREFIX}/lib ${CHECK_LIBDIR} ${CHECK_LIBRARY_DIRS})

    include(FindPackageHandleStandardArgs)

    find_package_handle_standard_args(CHECK DEFAULT_MSG CHECK_LIBRARY CHECK_INCLUDE_DIR)

    mark_as_advanced(CHECK_INCLUDE_DIR CHECK_LIBRARY)

endif()
