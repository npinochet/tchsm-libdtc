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

#ifndef TCBHSM_SLOT_H
#define TCBHSM_SLOT_H

#include "config.h"
#include <string>
#include <map>
#include <memory>

#include "Mutex.h"
#include "pkcs11.h"
#include "Configuration.h"

namespace hsm
{

class Application;

class Token;
class Session;
class Configuration;

using TokenPtr = std::unique_ptr<Token>;
using SessionPtr = std::unique_ptr<Session>;

/// Clase que representa un espacio para un token en el HSM
class Slot
{
    CK_SLOT_ID slotId_;
    Application & application_;
    CK_FLAGS slotFlags_;

    std::map<CK_SESSION_HANDLE, SessionPtr> sessions_;
    // A token can be unplugged...
    TokenPtr token_;
    Mutex mutex_;

public:
    Slot ( CK_SLOT_ID id, Application& application );
    Slot ( Slot & ) = delete;
    Slot (Slot && ) = default;
    Slot & operator=(Slot &) = delete;
    Slot & operator=(Slot &&) = default;
    ~Slot() = default;

    CK_SESSION_HANDLE openSession ( CK_FLAGS flags );
    void closeSession ( CK_SESSION_HANDLE handle );
    void closeAllSessions();
    Session & getSession ( CK_SESSION_HANDLE handle );
    bool hasSession ( CK_SESSION_HANDLE handle );
    CK_ULONG sessionsCount();

    Application & getApplication();
    CK_SLOT_ID getId() const;
    void getInfo ( CK_SLOT_INFO_PTR pInfo ) const; // throws exception
    void insertToken ( Token * token );
    Token & getToken() const; // throws exception
    bool isTokenPresent() const;
};
}

#endif // TCBHSM_SLOT_H
