# Copyright (C) 2014  Francisco Cifuentes <francisco@niclabs.cl>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# - Try to find LibConfig
# Once done this will define
#  LIBCONFIG_FOUND - System has LIBCONFIG
#  LIBCONFIG_INCLUDE_DIRS - The LIBCONFIG include directories
#  LIBCONFIG_LIBRARIES - The libraries needed to use LIBCONFIG
#  LIBCONFIG_DEFINITIONS - Compiler switches required for using LIBCONFIG

find_package(PkgConfig)
pkg_check_modules(PC_LIBCONFIG QUIET libconfig)
set(LIBCONFIG_DEFINITIONS ${PC_LIBCONFIG_CFLAGS_OTHER})

find_path(LIBCONFIG_INCLUDE_DIR libconfig.h
          HINTS ${PC_LIBCONFIG_INCLUDEDIR} ${PC_LIBCONFIG_INCLUDE_DIRS}
          PATH_SUFFIXES libconfig)

find_library(LIBCONFIG_LIBRARY NAMES libconfig config
             HINTS ${PC_LIBCONFIG_LIBDIR} ${PC_LIBCONFIG_LIBRARY_DIRS})

set(LIBCONFIG_LIBRARIES ${LIBCONFIG_LIBRARY})
set(LIBCONFIG_INCLUDE_DIRS ${LIBCONFIG_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(LibConfig DEFAULT_MSG
                                  LIBCONFIG_LIBRARY LIBCONFIG_INCLUDE_DIR)

mark_as_advanced(LIBCONFIG_INCLUDE_DIR LIBCONFIG_LIBRARY)
