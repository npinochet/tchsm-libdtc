add_subdirectory(core)

option(ENABLE_CRYPTOKI "Enable the pkcs11 lib" ON)
option(ENABLE_NODE "Enable the tchsm node" ON)

if(ENABLE_CRYPTOKI)
    add_subdirectory(cryptoki)
 endif()

if(ENABLE_NODE)
    add_subdirectory(node)
endif()

set(TCHSMLibDTC_VERSION_MAJOR 0)
set(TCHSMLibDTC_VERSION_MINOR 1)

configure_file(
    "${PROJECT_SOURCE_DIR}/src/include/dtc.h.in"
    "${PROJECT_BINARY_DIR}/include/dtc.h"
    )

install(FILES "${PROJECT_BINARY_DIR}/include/dtc.h" DESTINATION include)
