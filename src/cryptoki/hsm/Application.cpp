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

#include "Application.h"
#include "CryptoObject.h"
#include "Slot.h"
#include "Session.h"
#include "Token.h"
#include "TcbError.h"

#include <cstdlib> // getenv
#include <ostream>
#include <iostream>
#include <unistd.h>

using namespace hsm;


Application::Application(std::ostream &out)
        : out_(out) {
    static const char *env_config_file_path = "TCHSM_CONFIG";
    // First, read and setup the configuration.
    char const *configPath = std::getenv(env_config_file_path);
    if (configPath == nullptr) {
        throw TcbError("Application::Application",
                       std::string(env_config_file_path) +
                            " environment variable has not been set.",
                       CKR_DEVICE_ERROR);
    }

    configuration_.load(configPath);
    database_ = Database(configuration_.getDatabasePath());

    // By design, we will have one slot per configured token.
    // The tokens are owned by the slots.
    CK_SLOT_ID i = 0;
    for (Configuration::SlotConf const &slotConf: configuration_.getSlotConf()) {
        Slot *slot = new Slot(i, *this);

        slot->insertToken(database_.getToken(slotConf.label));

        slots_.push_back(SlotPtr(slot));
        ++i;
    }

    int err;
    dtcCtx_.reset(dtc_init_from_struct(configuration_.getDtcConf().get(), &err));
    if (!dtcCtx_) {
        throw TcbError("Application::Application", dtc_get_error_msg(err), CKR_DEVICE_ERROR);
    }

    // TODO: Slow joiner!
    sleep(1);


}

Application::~Application() {
    for (auto const &slotPtr: slots_) {
        getDatabase().saveToken(slotPtr->getToken());
    }

    dtcCtx_.reset();
}

void Application::errorLog(std::string message) const {
    out_ << message << std::endl;
}

Session &Application::getSession(CK_SESSION_HANDLE session) {
    return getSessionSlot(session).getSession(session);
}

const std::vector<SlotPtr> &Application::getSlotList() const {
    return slots_;
}

Slot &Application::getSlot(CK_SLOT_ID id) const {
    unsigned int i = static_cast<unsigned int> ( id );
    try {
        Slot &slot = *(slots_.at(i));
        return slot;
    } catch (std::out_of_range &e) {
        throw TcbError("Application::getSlot", e.what(), CKR_SLOT_ID_INVALID);
    }
}

Slot &Application::getSessionSlot(CK_SESSION_HANDLE handle) {
    for (auto &slotPtr: slots_) {
        if (slotPtr->hasSession(handle)) {
            return *slotPtr;
        }
    }

    throw TcbError("Application::getSessionSlot",
                   "Session not found.",
                   CKR_SESSION_HANDLE_INVALID);
}

Database &Application::getDatabase() {
    return database_;
}

const Configuration &Application::getConfiguration() const {
    return configuration_;
}

dtc_ctx_t *Application::getDtcContext() {
    return dtcCtx_.get();
}
