# - Try to find the CHECK libraries
#  Once done this will define
#
#  CHECK_FOUND - system has check
#  CHECK_INCLUDE_DIRS - the check include directory
#  CHECK_LIBRARIES - check library

IF ( CHECK_INCLUDE_DIR AND CHECK_LIBRARY)
    SET(CHECK_FOUND TRUE)
ELSE()
    find_package(PkgConfig)
    pkg_check_modules(CHECK QUIET check)

    find_path(CHECK_INCLUDE_DIR check.h
        HINTS ${CMAKE_INSTALL_PREFIX}/include ${CHECK_INCLUDEDIR} ${CHECK_INCLUDE_DIRS} PATH_SUFFIXES check)

    find_library(CHECK_LIBRARY NAMES check
        HINTS ${CMAKE_INSTALL_PREFIX}/lib ${CHECK_LIBDIR} ${CHECK_LIBRARY_DIRS})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(CHECK "check" CHECK_LIBRARY CHECK_LIBRARIES CHECK_INCLUDE_DIR )
    MARK_AS_ADVANCED(CHECK_INCLUDE_DIR CHECK_LIBRARIES)

ENDIF ()
