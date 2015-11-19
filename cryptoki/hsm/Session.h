/*
Copyright 2013 NIC Chile Research Labs.
This file is part of PKCS11-TsCrypto.

PKCS11-TsCrypto is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PKCS11-TsCrypto is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with PKCS11-TsCrypto.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef TCBHSM_SESSION_H
#define TCBHSM_SESSION_H

#include "config.h"

#include "pkcs11.h"
#include <dtc.h>

#include <memory>
#include <vector>
#include <utility>
#include <botan/hash.h>

namespace hsm {

    using KeyPair = std::pair<CK_OBJECT_HANDLE, CK_OBJECT_HANDLE>; // (Private, Public)

    class Configuration;

    class Slot;

    class CryptoObject;

// Sessions are enclosed in operations with objects, Tokens on containing objects.
    class Session {
        // Parent..
        Slot &slot_;

        const CK_SESSION_HANDLE handle_;
        const CK_FLAGS flags_;

        // Future use
        const CK_VOID_PTR application_;
        const CK_NOTIFY notify_;

        // Object Search
        bool findInitialized_ = false;
        std::vector<CK_OBJECT_HANDLE> foundObjects_;
        std::vector<CK_OBJECT_HANDLE>::iterator foundObjectsIterator_;
        std::vector<CK_OBJECT_HANDLE>::iterator foundObjectsEnd_;

        // Signing (remotely)
        bool signInitialized_ = false;
        CK_MECHANISM_TYPE signMechanism_;
        std::string signHandler_;
        key_metainfo_t *keyMetainfo_;

        // Digest
        Botan::HashFunction *hashFunction_;
        bool digestInitialized_ = false;

    public:
        Session(CK_FLAGS flags, CK_VOID_PTR pApplication,
                CK_NOTIFY notify, Slot &currentSlot);

        ~Session();

        CK_SESSION_HANDLE getHandle() const;

        CK_STATE getState() const;

        CK_FLAGS getFlags() const;

        void getSessionInfo(CK_SESSION_INFO_PTR pInfo) const;

        bool isReadOnly() const;

        Slot &getCurrentSlot();

        void login(CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

        void logout();

        // Cryptographic functions
        KeyPair generateKeyPair(CK_MECHANISM_PTR pMechanism,
                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                CK_ULONG ulPublicKeyAttributeCount,
                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                CK_ULONG ulPrivateKeyAttributeCount);

        void signInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

        void sign(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen);

        void digestInit(CK_MECHANISM_PTR pMechanism);

        void digest(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen);

        void seedRandom(CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);

        void generateRandom(CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

        CK_OBJECT_HANDLE createObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount); // throws exception

        void destroyObject(CK_OBJECT_HANDLE hObject); // throws exception

        void findObjectsInit(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

        std::vector<CK_OBJECT_HANDLE> findObjects(CK_ULONG maxObjectCount);

        void findObjectsFinal();

        CryptoObject &getObject(CK_OBJECT_HANDLE objectHandle); // throws exception
    };

}

#endif // TCBHSM_SESSION_H
