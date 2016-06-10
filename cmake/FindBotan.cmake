# - Try to find the Botan library
#
# Once done this will define
#
#  BOTAN_FOUND - System has Botan
#  BOTAN_INCLUDE_DIR - The Botan include directory
#  BOTAN_LIBRARIES - The libraries needed to use Botan
#  BOTAN_DEFINITIONS - Compiler switches required for using Botan

IF (BOTAN_INCLUDE_DIR AND BOTAN_LIBRARY)
    # in cache already
    SET(Botan_FIND_QUIETLY TRUE)
ENDIF (BOTAN_INCLUDE_DIR AND BOTAN_LIBRARY)

IF (NOT WIN32)
    # try using pkg-config to get the directories and then use these values
    # in the FIND_PATH() and FIND_LIBRARY() calls
    # also fills in BOTAN_DEFINITIONS, although that isn't normally useful
    FIND_PACKAGE(PkgConfig)
    PKG_SEARCH_MODULE(PC_BOTAN botan-1.11 botan-1.10 botan-1.9 botan-1.8 botan)
    SET(BOTAN_DEFINITIONS ${PC_BOTAN_CFLAGS})
ENDIF (NOT WIN32)

FIND_PATH(BOTAN_INCLUDE_DIR botan/botan.h
        HINTS
        ${PC_BOTAN_INCLUDEDIR}
        ${PC_BOTAN_INCLUDE_DIRS}
        )

FIND_LIBRARY(BOTAN_LIBRARY NAMES ${PC_BOTAN_LIBRARIES}
        HINTS
        ${PC_BOTAN_LIBDIR}
        ${PC_BOTAN_LIBRARY_DIRS}
        )

MARK_AS_ADVANCED(BOTAN_INCLUDE_DIR BOTAN_LIBRARY)

# handle the QUIETLY and REQUIRED arguments and set BOTAN_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Botan DEFAULT_MSG BOTAN_LIBRARY BOTAN_INCLUDE_DIR)

IF(BOTAN_FOUND)
    # If found and version requested, check it.
    IF(Botan_FIND_VERSION)
        set(VERSION_REGEX ".*libbotan-([0-9]+)\\.([0-9]+).*\\.(so|dylib).*")
        string(REGEX REPLACE ${VERSION_REGEX} "\\1" _BOTAN_VERSION_MAJOR ${BOTAN_LIBRARY})
        string(REGEX REPLACE ${VERSION_REGEX} "\\2" _BOTAN_VERSION_MINOR ${BOTAN_LIBRARY})
        set(_BOTAN_FOUND_VERSION "${_BOTAN_VERSION_MAJOR}.${_BOTAN_VERSION_MINOR}")

        IF("${_BOTAN_FOUND_VERSION}" VERSION_LESS "${Botan_FIND_VERSION}")
            set(VERSION_OK 0)
        ELSEIF(Botan_FIND_VERSION_EXACT AND NOT "${_BOTAN_FOUND_VERSION}" VERSION_EQUAL "${Botan_FIND_VERSION}")
            set(VERSION_OK 0)
        ELSE()
            set(VERSION_OK 1)
        ENDIF()

        IF(VERSION_OK)
            SET(BOTAN_LIBRARIES    ${BOTAN_LIBRARY})
            SET(BOTAN_INCLUDE_DIRS ${BOTAN_INCLUDE_DIR})
        ELSE()
            set(BOTAN_FOUND 0)
            message(SEND_ERROR "Botan version found (${_BOTAN_FOUND_VERSION}). Requested: ${Botan_FIND_VERSION}")
        ENDIF()
    ELSE()
        SET(BOTAN_LIBRARIES    ${BOTAN_LIBRARY})
        SET(BOTAN_INCLUDE_DIRS ${BOTAN_INCLUDE_DIR})
    ENDIF()
ENDIF()
