add_subdirectory(core)

option(ENABLE_CRYPTOKI "Enable the pkcs11 lib" ON)
option(ENABLE_NODE "Enable the tchsm node" ON)

if(ENABLE_CRYPTOKI)
    add_subdirectory(cryptoki)
 endif()

if(ENABLE_NODE)
    add_subdirectory(node)
endif()

install(FILES include/dtc.h DESTINATION include)
