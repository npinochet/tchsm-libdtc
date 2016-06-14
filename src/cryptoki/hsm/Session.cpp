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

#include <algorithm>

#include <botan/emsa.h>
#include <botan/md5.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>

#include <botan/rsa.h>

#include <sstream>

#include <pkcs11.h>
#include <dtc.h>
#include <iostream>
#include <botan/lookup.h>
#include <uuid/uuid.h>

#include "Session.h"
#include "Slot.h"
#include "Token.h"
#include "CryptoObject.h"
#include "TcbError.h"
#include "Application.h"

using namespace hsm;
using namespace std;

namespace {

    bool userAuthorization(CK_STATE sessionState, CK_BBOOL isTokenObject,
                           CK_BBOOL isPrivateObject, bool userAction) {
        switch (sessionState) {
            case CKS_RW_SO_FUNCTIONS:
                return isPrivateObject == CK_FALSE;

            case CKS_RW_USER_FUNCTIONS:
                return true;

            case CKS_RO_USER_FUNCTIONS:
                if (isTokenObject == CK_TRUE) {
                    return !userAction;
                } else {
                    return true;
                }

            case CKS_RW_PUBLIC_SESSION:
                return isPrivateObject == CK_FALSE;

            case CKS_RO_PUBLIC_SESSION:
                if (isPrivateObject == CK_FALSE) {
                    return (isTokenObject != CK_TRUE) || !userAction;
                } else {
                    return false;
                }

            default:
                break;
        }

        return false;
    }

    CK_SESSION_HANDLE actualHandle = 0;

    std::string get_uuid() {
        uuid_t uuid;
        char tmp_uuid[37];
        uuid_generate(uuid);
        uuid_unparse(uuid, tmp_uuid);
        return string(tmp_uuid);
    }
}

Session::Session(CK_FLAGS flags, Slot &currentSlot)
        : slot_(currentSlot),
          handle_(++actualHandle),
          flags_(flags),
          keyMetainfo_(nullptr) {

}

Session::~Session() {
    Token &token = slot_.getToken();
    auto &objects = token.getObjects();

    for (auto &objectPair: objects) {
        CryptoObject &object = *(objectPair.second);

        if (object.getType() == CryptoObjectType::SESSION_OBJECT) {

            CK_ATTRIBUTE tmpl = {.type=CKA_VENDOR_DEFINED};
            CK_ATTRIBUTE const *handlerAttribute = object.findAttribute(&tmpl);
            if (handlerAttribute != nullptr) {

                // If a keypair is stored, then each the public and the private key
                // will be deleted.
                // Neitherless if it's only one instance stored in the backend.
                string handler(static_cast<char *> ( handlerAttribute->pValue ), handlerAttribute->ulValueLen);
                dtc_delete_key_shares(getCurrentSlot().getApplication().getDtcContext(), handler.c_str());
            }

            objects.erase(objectPair.first);
        }
    }
}

CK_SESSION_HANDLE Session::getHandle() const {
    return handle_;
}

Slot &Session::getCurrentSlot() {
    return slot_;
}

void Session::getSessionInfo(CK_SESSION_INFO_PTR pInfo) const {
    if (pInfo != nullptr) {
        pInfo->slotID = slot_.getId();
        pInfo->state = getState();
        pInfo->flags = getFlags();
        pInfo->ulDeviceError = 0;
    } else {
        throw TcbError("Session::getSessionInfo", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }
}

CK_OBJECT_HANDLE Session::createObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    if (pTemplate == nullptr) {
        throw TcbError("Session::createObject", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    // Original from SoftHSM...
    CK_BBOOL isToken = CK_FALSE;
    CK_BBOOL isPrivate = CK_TRUE;
    CK_OBJECT_CLASS oClass = CKO_VENDOR_DEFINED;
    CK_KEY_TYPE keyType = CKK_VENDOR_DEFINED;

    // Extract object information
    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
            case CKA_TOKEN:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
                    isToken = *(CK_BBOOL *) pTemplate[i].pValue;
                }
                break;

            case CKA_PRIVATE:
                if (pTemplate[i].ulValueLen == sizeof(CK_BBOOL)) {
                    isPrivate = *(CK_BBOOL *) pTemplate[i].pValue;
                }
                break;

            case CKA_CLASS:
                if (pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
                    oClass = *(CK_OBJECT_CLASS *) pTemplate[i].pValue;
                }
                break;

            case CKA_KEY_TYPE:
                if (pTemplate[i].ulValueLen == sizeof(CK_KEY_TYPE)) {
                    keyType = *(CK_KEY_TYPE *) pTemplate[i].pValue;
                }
                break;
            default:
                break;
        }
    }

    if (isToken == CK_TRUE && this->isReadOnly()) {
        throw TcbError("Session::createObject", "session is read only.", CKR_SESSION_READ_ONLY);
    }

    if (!userAuthorization(getState(), isToken, isPrivate, true))
        throw TcbError("Session::createObject",
                       "user not logged in.",
                       CKR_USER_NOT_LOGGED_IN);

    switch (oClass) {
        case CKO_PUBLIC_KEY:
        case CKO_PRIVATE_KEY:
            if (keyType == CKK_RSA) {
                Token &token = slot_.getToken();
                CryptoObjectType objectType =
                        isToken ?
                        CryptoObjectType::TOKEN_OBJECT :
                        CryptoObjectType::SESSION_OBJECT;

                CryptoObject *object = new CryptoObject(pTemplate, ulCount, objectType);

                CK_OBJECT_HANDLE handle = token.addObject(object);
                // Update the database
                getCurrentSlot().getApplication().getDatabase().saveToken(token);
                return handle;
            } else {
                throw TcbError("Session::createObject",
                               "keyType not supported (yet).",
                               CKR_ATTRIBUTE_VALUE_INVALID);
            }
        default:
            throw TcbError("Session::createObject",
                           "object class not supported (yet).",
                           CKR_ATTRIBUTE_VALUE_INVALID);
    }

    // TODO: Verificar que los objetos sean validos.
}

void Session::destroyObject(CK_OBJECT_HANDLE hObject) {
    Token &token = slot_.getToken();
    auto &objectContainer = token.getObjects();

    auto it = objectContainer.find(hObject);
    if (it != objectContainer.end()) {
        // Verifico que el objeto no sea una llave, y si lo es, la elimino de los nodos.
        CK_ATTRIBUTE tmpl = {.type=CKA_VENDOR_DEFINED};
        const CK_ATTRIBUTE *handlerAttribute = it->second->findAttribute(&tmpl);
        if (handlerAttribute != nullptr) {
            string handler(static_cast<char *> ( handlerAttribute->pValue ), handlerAttribute->ulValueLen);
            dtc_delete_key_shares(getCurrentSlot().getApplication().getDtcContext(), handler.c_str());
        }

        objectContainer.erase(it);
        getCurrentSlot().getApplication().getDatabase().saveToken(token);
    } else {
        throw TcbError("Session::destroyObject", "object not found.", CKR_OBJECT_HANDLE_INVALID);
    }
}

void Session::findObjectsInit(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    // TODO: Verificar correctitud
    if (findInitialized_) {
        throw TcbError("Session::findObjectsInit", "operation already initialized.", CKR_OPERATION_ACTIVE);
    }
    if (pTemplate == nullptr) {
        throw TcbError("Session::findObjectsInit", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    Token &token = getCurrentSlot().getToken();

    if (ulCount == 0) {
        // Busco todos los objetos...
        for (auto &handleObjectPair: token.getObjects()) {
            foundObjects_.push_back(handleObjectPair.first);
        }
    } else {
        for (auto &handleObjectPair: token.getObjects()) {
            if (handleObjectPair.second->match(pTemplate, ulCount)) {
                foundObjects_.push_back(handleObjectPair.first);
            }
        }
    }

    //TODO: verificar permisos de acceso.
    foundObjectsIterator_ = foundObjects_.begin();
    foundObjectsEnd_ = foundObjects_.end();
    findInitialized_ = true;
}

vector<CK_OBJECT_HANDLE> Session::findObjects(CK_ULONG maxObjectCount) {
    if (!findInitialized_) {
        throw TcbError("Session::findObjects",
                       "operation not initialized.",
                       CKR_OPERATION_NOT_INITIALIZED);
    }

    auto end = foundObjectsIterator_ + maxObjectCount;
    if (foundObjectsEnd_ < end) {
        end = foundObjectsEnd_;
    }

    vector<CK_OBJECT_HANDLE> response(foundObjectsIterator_, end);
    foundObjectsIterator_ = end;
    return response;
}

void Session::findObjectsFinal() {
    if (!findInitialized_) {
        throw TcbError("Session::findObjects", "operation not initialized.",
                       CKR_OPERATION_NOT_INITIALIZED);
    } else {
        findInitialized_ = false;
    }
}


CryptoObject &Session::getObject(CK_OBJECT_HANDLE objectHandle) {
    try {
        return slot_.getToken().getObject(objectHandle);
    } catch (std::out_of_range &e) {
        throw TcbError("Session::getObject", "object doesn't exists.", CKR_OBJECT_HANDLE_INVALID);
    }
}


CK_STATE Session::getState() const {
    // TODO: Completar la semántica de lecto-escritura.
    switch (slot_.getToken().getSecurityLevel()) {
        case Token::SecurityLevel::SECURITY_OFFICER:
            return CKS_RW_SO_FUNCTIONS;
        case Token::SecurityLevel::USER:
            if (isReadOnly()) {
                return CKS_RO_USER_FUNCTIONS;
            } else {
                return CKS_RW_USER_FUNCTIONS;
            }
        case Token::SecurityLevel::PUBLIC:
            if (isReadOnly()) {
                return CKS_RO_PUBLIC_SESSION;
            } else {
                return CKS_RW_PUBLIC_SESSION;
            }
    }
}

bool Session::isReadOnly() const {
    return (flags_ & CKF_RW_SESSION) != CKF_RW_SESSION;
}

CK_FLAGS Session::getFlags() const {
    return flags_;
}

void Session::login(CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    Token &token = slot_.getToken();
    token.login(userType, pPin, ulPinLen);
}

void Session::logout() {
    slot_.getToken().logout();
}

namespace {
    CK_OBJECT_HANDLE createPublicKey(Session &session, CK_ATTRIBUTE_PTR pkTemplate, CK_ULONG pkAttrCount,
                                     const string &keyHandler, const key_metainfo_t *metainfo) {
        // NOTE: This comes in some way from SoftHSM...
        CK_OBJECT_CLASS oClass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE keyType = CKK_RSA;
        CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
        CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
        CK_DATE emptyDate;

        // Generic attributes...
        CK_ATTRIBUTE aClass = {CKA_CLASS, &oClass, sizeof(oClass)};
        CK_ATTRIBUTE aKeyType = {CKA_KEY_TYPE, &keyType, sizeof(keyType)};
        CK_ATTRIBUTE aMechType = {CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType)};
        CK_ATTRIBUTE aLocal = {CKA_LOCAL, &ckTrue, sizeof(ckTrue)};

        CK_ATTRIBUTE aLabel = {CKA_LABEL, NULL_PTR, 0};
        CK_ATTRIBUTE aId = {CKA_ID, NULL_PTR, 0};
        CK_ATTRIBUTE aSubject = {CKA_SUBJECT, NULL_PTR, 0};
        CK_ATTRIBUTE aPrivate = {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aModifiable = {CKA_MODIFIABLE, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aToken = {CKA_TOKEN, &ckFalse, sizeof(ckFalse)};
        CK_ATTRIBUTE aDerive = {CKA_DERIVE, &ckFalse, sizeof(ckFalse)};
        CK_ATTRIBUTE aEncrypt = {CKA_ENCRYPT, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aVerify = {CKA_VERIFY, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aVerifyRecover = {CKA_VERIFY_RECOVER, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aWrap = {CKA_WRAP, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aTrusted = {CKA_TRUSTED, &ckFalse, sizeof(ckFalse)};
        CK_ATTRIBUTE aStartDate = {CKA_START_DATE, &emptyDate, 0};
        CK_ATTRIBUTE aEndDate = {CKA_END_DATE, &emptyDate, 0};
        CK_ATTRIBUTE aModulusBits = {CKA_MODULUS_BITS, NULL_PTR, 0};


        string serializedMetainfo(tc_serialize_key_metainfo(metainfo));
        const public_key_t *pk = tc_key_meta_info_public_key(metainfo);
        const bytes_t *modulus = tc_public_key_n(pk);
        const bytes_t *publicExponent = tc_public_key_e(pk);


        CK_ATTRIBUTE aValue = {
                .type=CKA_VENDOR_DEFINED,
                .pValue= (void *) keyHandler.c_str(),
                .ulValueLen=keyHandler.size()
        };

        CK_ATTRIBUTE aMetainfo = {
                .type=CKA_VENDOR_DEFINED + 1,
                .pValue= (void *) serializedMetainfo.c_str(),
                .ulValueLen=serializedMetainfo.size()
        };

        CK_ATTRIBUTE aModulus = {
                .type = CKA_MODULUS,
                .pValue = modulus->data,
                .ulValueLen = modulus->data_len
        };

        CK_ATTRIBUTE aExponent = {
                .type = CKA_PUBLIC_EXPONENT,
                .pValue = publicExponent->data,
                .ulValueLen = publicExponent->data_len
        };

        for (CK_ULONG i = 0; i < pkAttrCount; i++) {
            switch (pkTemplate[i].type) {
                case CKA_LABEL:
                    aLabel = pkTemplate[i];
                    break;
                case CKA_ID:
                    aId = pkTemplate[i];
                    break;
                case CKA_SUBJECT:
                    aSubject = pkTemplate[i];
                    break;
                case CKA_DERIVE:
                    aDerive = pkTemplate[i];
                    break;
                case CKA_TOKEN:
                    aToken = pkTemplate[i];
                    break;
                case CKA_PRIVATE:
                    aPrivate = pkTemplate[i];
                    break;
                case CKA_MODIFIABLE:
                    aModifiable = pkTemplate[i];
                    break;
                case CKA_ENCRYPT:
                    aEncrypt = pkTemplate[i];
                    break;
                case CKA_VERIFY:
                    aVerify = pkTemplate[i];
                    break;
                case CKA_VERIFY_RECOVER:
                    aVerifyRecover = pkTemplate[i];
                    break;
                case CKA_WRAP:
                    aWrap = pkTemplate[i];
                    break;
                case CKA_TRUSTED:
                    aSubject = pkTemplate[i];
                    break;
                case CKA_START_DATE:
                    aStartDate = pkTemplate[i];
                    break;
                case CKA_END_DATE:
                    aEndDate = pkTemplate[i];
                    break;
                case CKA_MODULUS_BITS:
                    aModulusBits = pkTemplate[i];
                    break;
                default:
                    break;
            }
        }

        CK_ATTRIBUTE attributes[] = {
                aClass,
                aKeyType,
                aMechType,
                aLocal,
                aLabel,
                aId,
                aSubject,
                aPrivate,
                aModifiable,
                aToken,
                aDerive,
                aEncrypt,
                aVerify,
                aVerifyRecover,
                aWrap,
                aTrusted,
                aStartDate,
                aEndDate,
                aValue,
                aMetainfo,
                aModulus,
                aModulusBits,
                aExponent
        };

        return session.createObject(attributes, sizeof(attributes) / sizeof(attributes[0]));
    }

    CK_OBJECT_HANDLE createPrivateKey(Session &session, CK_ATTRIBUTE_PTR skTemplate, CK_ULONG skAttrCount,
                                      string const &keyHandler, const key_metainfo_t *metainfo) {
        CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = CKK_RSA;
        CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
        CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
        CK_DATE emptyDate;

        // Default attributes...
        CK_ATTRIBUTE aClass = {CKA_CLASS, &oClass, sizeof(oClass)};
        CK_ATTRIBUTE aKeyType = {CKA_KEY_TYPE, &keyType, sizeof(keyType)};
        CK_ATTRIBUTE aMechType = {CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType)};
        CK_ATTRIBUTE aLocal = {CKA_LOCAL, &ckTrue, sizeof(ckTrue)};

        CK_ATTRIBUTE aLabel = {CKA_LABEL, NULL_PTR, 0};
        CK_ATTRIBUTE aId = {CKA_ID, NULL_PTR, 0};
        CK_ATTRIBUTE aSubject = {CKA_SUBJECT, NULL_PTR, 0};
        CK_ATTRIBUTE aPrivate = {CKA_PRIVATE, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aModifiable = {CKA_MODIFIABLE, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aToken = {CKA_TOKEN, &ckFalse, sizeof(ckFalse)};
        CK_ATTRIBUTE aDerive = {CKA_DERIVE, &ckFalse, sizeof(ckFalse)};

        CK_ATTRIBUTE aWrapWithTrusted = {CKA_WRAP_WITH_TRUSTED, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aAlwaysAuthenticate = {CKA_ALWAYS_AUTHENTICATE, &ckFalse, sizeof(ckFalse)};
        CK_ATTRIBUTE aSensitive = {CKA_SENSITIVE, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aAlwaysSensitive = {CKA_ALWAYS_SENSITIVE, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aDecrypt = {CKA_DECRYPT, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aSign = {CKA_SIGN, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aSignRecover = {CKA_SIGN_RECOVER, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aUnwrap = {CKA_UNWRAP, &ckTrue, sizeof(ckTrue)};
        CK_ATTRIBUTE aExtractable = {CKA_EXTRACTABLE, &ckFalse, sizeof(ckFalse)};
        CK_ATTRIBUTE aNeverExtractable = {CKA_NEVER_EXTRACTABLE, &ckTrue, sizeof(ckTrue)};

        CK_ATTRIBUTE aStartDate = {CKA_START_DATE, &emptyDate, 0};
        CK_ATTRIBUTE aEndDate = {CKA_END_DATE, &emptyDate, 0};

        string serializedMetainfo(tc_serialize_key_metainfo(metainfo));

        const public_key_t *pk = tc_key_meta_info_public_key(metainfo);
        const bytes_t *modulus = tc_public_key_n(pk);
        const bytes_t *publicExponent = tc_public_key_e(pk);

        // With this we can use the standard mechanism to store objects
        CK_ATTRIBUTE aValue = {
                .type=CKA_TC_KEYHANDLER,
                .pValue= (void *) keyHandler.c_str(),
                .ulValueLen = keyHandler.size()
        };

        CK_ATTRIBUTE aMetainfo = {
                .type=CKA_TC_KEYMETAINFO,
                .pValue= (void *) serializedMetainfo.c_str(),
                .ulValueLen=serializedMetainfo.size()
        };

        CK_ATTRIBUTE aModulus = {
                .type = CKA_MODULUS,
                .pValue = modulus->data,
                .ulValueLen = modulus->data_len
        };

        CK_ATTRIBUTE aExponent = {
                .type = CKA_PUBLIC_EXPONENT,
                .pValue = publicExponent->data,
                .ulValueLen = publicExponent->data_len
        };

        for (CK_ULONG i = 0; i < skAttrCount; i++) {
            switch (skTemplate[i].type) {
                case CKA_LABEL:
                    aLabel = skTemplate[i];
                    break;
                case CKA_ID:
                    aId = skTemplate[i];
                    break;
                case CKA_SUBJECT:
                    aSubject = skTemplate[i];
                    break;
                case CKA_TOKEN:
                    aToken = skTemplate[i];
                    break;
                case CKA_PRIVATE:
                    aPrivate = skTemplate[i];
                    break;
                case CKA_DERIVE:
                    aDerive = skTemplate[i];
                    break;
                case CKA_MODIFIABLE:
                    aModifiable = skTemplate[i];
                    break;
                case CKA_DECRYPT:
                    aDecrypt = skTemplate[i];
                    break;
                case CKA_SIGN:
                    aSign = skTemplate[i];
                    break;
                case CKA_SIGN_RECOVER:
                    aSignRecover = skTemplate[i];
                    break;
                case CKA_UNWRAP:
                    aUnwrap = skTemplate[i];
                    break;
                case CKA_WRAP_WITH_TRUSTED:
                    aWrapWithTrusted = skTemplate[i];
                    break;
                case CKA_ALWAYS_AUTHENTICATE:
                    aAlwaysAuthenticate = skTemplate[i];
                    break;
                case CKA_START_DATE:
                    aStartDate = skTemplate[i];
                    break;
                case CKA_END_DATE:
                    aEndDate = skTemplate[i];
                    break;
                default:
                    break;
            }
        }

        CK_ATTRIBUTE attributes[] = {
                aClass,
                aKeyType,
                aMechType,
                aLocal,

                aLabel,
                aId,
                aSubject,
                aPrivate,
                aModifiable,
                aToken,
                aDerive,
                aWrapWithTrusted,
                aAlwaysAuthenticate,
                aSensitive,
                aAlwaysSensitive,
                aDecrypt,
                aSign,
                aSignRecover,
                aUnwrap,
                aExtractable,
                aNeverExtractable,
                aValue,
                aMetainfo,
                aModulus,
                aExponent,

                aStartDate,
                aEndDate
        };

        return session.createObject(attributes, sizeof(attributes) / sizeof(attributes[0]));
    }

}

KeyPair Session::generateKeyPair(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pkTemplate, CK_ULONG pkAttrCount,
                                 CK_ATTRIBUTE_PTR skTemplate, CK_ULONG skAttrCount) {
    // TODO: verificar permisos de acceso.
    if (pMechanism == nullptr || pkTemplate == nullptr || skTemplate == nullptr) {
        throw TcbError("Session::generateKeyPair", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    CK_ULONG modulusBits = 0;

    // With this we can get RAII semantics (c++ memsafe things).
    std::unique_ptr<bytes_t, std::function<void(bytes_t*)>> publicExponent(nullptr, [](bytes_t *p) {
        tc_release_bytes(p, NULL);
    });

    for (CK_ULONG i = 0; i < pkAttrCount; i++) {
        switch (pkTemplate[i].type) {
            case CKA_MODULUS_BITS: {
                if (pkTemplate[i].ulValueLen != sizeof(CK_ULONG)) {
                    throw TcbError("Session::generateKeyPair", "template incomplete.",
                                   CKR_TEMPLATE_INCOMPLETE);
                }
                modulusBits = *static_cast<CK_ULONG *> ( pkTemplate[i].pValue );
            }
                break;
            case CKA_PUBLIC_EXPONENT: {
                publicExponent.reset(tc_init_bytes(pkTemplate[i].pValue, pkTemplate[i].ulValueLen));
            }
                break;
            default:
                break;
        }
    }

    if (modulusBits == 0) {
        throw TcbError("Session::generateKeyPair", "template incomplete.", CKR_TEMPLATE_INCOMPLETE);
    }

    switch (pMechanism->mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN: {
            // RSA is the only accepted method...
            string keyHandler = get_uuid();
            // TODO: check if generated uuid is already taken.

            Application &app = getCurrentSlot().getApplication();

            dtc_ctx_t *ctx = app.getDtcContext();
            const Configuration &cfg = app.getConfiguration();

            key_metainfo_t *metainfo;
            int err = dtc_generate_key_shares(ctx, keyHandler.c_str(), modulusBits, cfg.getThreshold(),
                                              cfg.getNodesNumber(), publicExponent.get(), &metainfo);
            if (err != DTC_ERR_NONE) {
                throw TcbError("Session::generateKeyPair", std::string(dtc_get_error_msg(err)), CKR_GENERAL_ERROR);
            }

            CK_OBJECT_HANDLE sk = createPrivateKey(*this, skTemplate, skAttrCount, keyHandler, metainfo);
            CK_OBJECT_HANDLE pk = createPublicKey(*this, pkTemplate, pkAttrCount, keyHandler, metainfo);
            return KeyPair(sk, pk);
        }
        default:
            throw TcbError("Session::generateKeyPair", "mechanism invalid.", CKR_MECHANISM_INVALID);
    }
}

void Session::signInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (signInitialized_) {
        throw TcbError("Session::signInit", "operation active.", CKR_OPERATION_ACTIVE);
    }

    CryptoObject &keyObject = getObject(hKey);
    CK_ATTRIBUTE tmpl = {.type = CKA_VENDOR_DEFINED};

    const CK_ATTRIBUTE *keyName = keyObject.findAttribute(&tmpl);
    if (!keyName) {
        throw TcbError("Session::signInit", "object handle doesn't contains any key.", CKR_ARGUMENTS_BAD);
    }

    tmpl = {.type = CKA_VENDOR_DEFINED + 1};
    const CK_ATTRIBUTE *keyMetainfoAttribute = keyObject.findAttribute(&tmpl);
    if (!keyMetainfoAttribute) {
        throw TcbError("Session::signInit", "object handle doesn't contains any key metainfo.", CKR_ARGUMENTS_BAD);
    }

    string metainfo(static_cast<char *>(keyMetainfoAttribute->pValue), keyMetainfoAttribute->ulValueLen);
    keyMetainfo_.reset(tc_deserialize_key_metainfo(metainfo.c_str()));

    string keyHandler(static_cast<char *>(keyName->pValue), keyName->ulValueLen);
    keyHandler_ = keyHandler;

    CK_MECHANISM_TYPE signMechanism = pMechanism->mechanism;

    std::string emsa;
    switch (signMechanism) {
        case CKM_RSA_PKCS:
            emsa = "EMSA3(Raw)";
            break;

        case CKM_MD5_RSA_PKCS:
            emsa = "EMSA3(MD5)";
            break;

        case CKM_SHA1_RSA_PKCS:
            emsa = "EMSA3(SHA-160)";
            break;

        case CKM_SHA1_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-160)";
            break;

        case CKM_SHA256_RSA_PKCS:
            emsa = "EMSA3(SHA-256)";
            break;

        case CKM_SHA256_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-256)";
            break;

        case CKM_SHA384_RSA_PKCS:
            emsa = "EMSA3(SHA-384)";
            break;

        case CKM_SHA384_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-384)";
            break;

        case CKM_SHA512_RSA_PKCS:
            emsa = "EMSA3(SHA-512)";
            break;

        case CKM_SHA512_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-512)";
            break;

        default:
            throw TcbError("Session::sign", "mechanism Invalid.", CKR_MECHANISM_INVALID);
    }

    padder_.reset(Botan::get_emsa(emsa));

    signInitialized_ = true;
}


void Session::signUpdate(CK_BYTE_PTR pData, CK_ULONG ulDataLen) {
    if (!signInitialized_) {
        throw TcbError("Session::signUpdate", "operation not initialized.", CKR_OPERATION_NOT_INITIALIZED);
    }

    padder_->update(pData, ulDataLen);
}


void Session::signFinal(CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    if (!signInitialized_) {
        throw TcbError("Session::signFinal", "operation not initialized.", CKR_OPERATION_NOT_INITIALIZED);
    }

    const public_key_t *pk = tc_key_meta_info_public_key(&*keyMetainfo_);
    const bytes_t *nBytes = tc_public_key_n(pk);
    // TODO: Check how much bytes do we need to give when pSignature is null.
    if(pSignature == nullptr) {
        *pulSignatureLen = nBytes->data_len;
        return;
    }

    Botan::BigInt n(static_cast<Botan::byte *>(nBytes->data), nBytes->data_len);

    Botan::AutoSeeded_RNG rng;
    auto paddedData = padder_->encoding_of(padder_->raw_data(), n.bits()-1, rng);
    bytes_t paddedDataBytes = { &paddedData[0], static_cast<uint32_t>(paddedData.size()) };

    dtc_ctx_t *ctx = getCurrentSlot().getApplication().getDtcContext();

    bytes_t *signature;
    int sign_err = dtc_sign(ctx, keyMetainfo_.get(), keyHandler_.c_str(), &paddedDataBytes, &signature);
    if (sign_err != DTC_ERR_NONE) {
        string err_msg = "DT_TC Error: ";
        throw TcbError("Session::sign", err_msg + dtc_get_error_msg(sign_err), CKR_GENERAL_ERROR);
    }

    if (*pulSignatureLen < signature->data_len) {

        throw TcbError("Session::sign", "buffer too small.", CKR_BUFFER_TOO_SMALL);
    }
    *pulSignatureLen = signature->data_len;

    CK_BYTE_PTR data = (CK_BYTE_PTR) signature->data;
    uint32_t dataLen = signature->data_len;
    std::copy(data, data + dataLen, pSignature);

    keyMetainfo_.reset();
    padder_.reset();
    signInitialized_ = false;
}

void Session::verifyInit(CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    if (verifyInitialized_) {
        throw TcbError("Session::verifyInit", "operation active.", CKR_OPERATION_ACTIVE);
    }

    CryptoObject &keyObject = getObject(hKey);
    CK_ATTRIBUTE publicExponentAttr;
    CK_ATTRIBUTE modulusAttr;
    try {
        publicExponentAttr = keyObject.getAttributes().at(CKA_PUBLIC_EXPONENT);
        modulusAttr = keyObject.getAttributes().at(CKA_MODULUS);
    } catch (std::out_of_range &e) {
        throw TcbError("Session::verifyInit",
                       "keyObject doesn't have public exponent or modulus.",
                       CKR_OBJECT_HANDLE_INVALID);
    }

    CK_MECHANISM_TYPE signMechanism = pMechanism->mechanism;
    std::string emsa;
    switch (signMechanism) {
        case CKM_RSA_PKCS:
            emsa = "EMSA3(Raw)";
            break;

        case CKM_MD5_RSA_PKCS:
            emsa = "EMSA3(MD5)";
            break;

        case CKM_SHA1_RSA_PKCS:
            emsa = "EMSA3(SHA-160)";
            break;

        case CKM_SHA1_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-160)";
            break;

        case CKM_SHA256_RSA_PKCS:
            emsa = "EMSA3(SHA-256)";
            break;

        case CKM_SHA256_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-256)";
            break;

        case CKM_SHA384_RSA_PKCS:
            emsa = "EMSA3(SHA-384)";
            break;

        case CKM_SHA384_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-384)";
            break;

        case CKM_SHA512_RSA_PKCS:
            emsa = "EMSA3(SHA-512)";
            break;

        case CKM_SHA512_RSA_PKCS_PSS:
            emsa = "EMSA4(SHA-512)";
            break;

        default:
            throw TcbError("Session::sign", "mechanism not supported (yet).", CKR_MECHANISM_INVALID);
    }

    Botan::BigInt e((Botan::byte *) publicExponentAttr.pValue, publicExponentAttr.ulValueLen);
    Botan::BigInt n((Botan::byte *) modulusAttr.pValue, modulusAttr.ulValueLen);

    pk_.reset(new Botan::RSA_PublicKey(n, e));
    verifier_.reset(new Botan::PK_Verifier(*pk_, emsa));

    verifyInitialized_ = true;
}

void Session::verifyUpdate(CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    if (!verifyInitialized_) {
        throw TcbError("Session::verifyUpdate", "operation not initialized.", CKR_OPERATION_NOT_INITIALIZED);
    }

    verifier_->update(pPart, ulPartLen);
}

bool Session::verifyFinal(CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen) {
    if (!verifyInitialized_) {
        throw TcbError("Session::verifyFinal", "operation not initialized.", CKR_OPERATION_NOT_INITIALIZED);
    }

    bool checks = verifier_->check_signature(pSignature, ulSignatureLen);

    verifier_.reset();
    pk_.reset();
    verifyInitialized_ = false;

    return checks;
}

void Session::digestInit(CK_MECHANISM_PTR pMechanism) {
    if (digestInitialized_) {
        throw TcbError("Session::digestInit", "operation active.", CKR_OPERATION_ACTIVE);
    }

    if (pMechanism == nullptr) {
        throw TcbError("Session::digestInit", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    Botan::HashFunction *f;
    switch (pMechanism->mechanism) {
        case CKM_MD5:
            f = new Botan::MD5;
            break;
        case CKM_SHA_1:
            f = new Botan::SHA_160;
            break;
        case CKM_SHA256:
            f = new Botan::SHA_256;
            break;
        case CKM_SHA384:
            f = new Botan::SHA_384;
            break;
        case CKM_SHA512:
            f = new Botan::SHA_512;
            break;
        default:
            throw TcbError("Session::digestInit", "Mechanism invalid.", CKR_MECHANISM_INVALID);
    }
    hashFunction_.reset(f);

    digestInitialized_ = true;
}

void Session::digest(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen) {
    if (!digestInitialized_) {
        throw TcbError("Session::digest", "operation not initialized.", CKR_OPERATION_NOT_INITIALIZED);
    }

    if (pulDigestLen == nullptr) {
        throw TcbError("Session::digest", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    size_t digestSize = hashFunction_->output_length();

    if (pDigest == nullptr) {
        *pulDigestLen = digestSize;
        return;
    }

    if (*pulDigestLen < digestSize) {
        *pulDigestLen = digestSize;
        throw TcbError("Session::digest", "buffer too small.", CKR_BUFFER_TOO_SMALL);
    }

    if (pData == nullptr) {
        throw TcbError("Session::digest", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    hashFunction_->update(pData, ulDataLen);

    *pulDigestLen = digestSize;

    hashFunction_->final(pDigest);
    digestInitialized_ = false;
    hashFunction_.reset();
}

void Session::generateRandom(CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen) {
    if (!pRandomData) {
        throw TcbError("Session::generateRandom", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    rng_.randomize(pRandomData, ulRandomLen);

}

void Session::seedRandom(CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen) {
    if (!pSeed) {
        throw TcbError("Session::seedRandom", "got NULL pointer.", CKR_ARGUMENTS_BAD);
    }

    rng_.add_entropy(pSeed, ulSeedLen);
}

