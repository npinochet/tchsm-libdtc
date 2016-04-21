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

#include <cerrno>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <libconfig.h>

#include "Configuration.h"
#include "TcbError.h"
#include "pkcs11.h"

using namespace hsm;

static uint16_t lookupUint16Value(config_setting_t *setting, const char *name) {
    long long aux_int64; //
    if(CONFIG_FALSE == config_setting_lookup_int64(setting, name, &aux_int64)) {
        throw std::invalid_argument::invalid_argument(name);
    }
    if(aux_int64 > UINT16_MAX) {
        throw std::overflow_error(name);
    }
    return static_cast<uint16_t>(aux_int64);
}

Configuration::Configuration(std::string configurationPath) {
    this->Configuration::load(configurationPath);
}

void Configuration::load(std::string configurationPath) {
    // As libdtc uses the C bindings for libconfig, we don't want to
    // introduce the c++ bindings as another dependency. That's why this method
    // is written using the C API of LibConfig.
    config_t cfg;
    config_setting_t *root;
    config_setting_t *cryptoki, *dtc, *slots, *slot;
    const char *aux_char;
    int64_t aux_int64;

    config_init(&cfg);

    if(CONFIG_TRUE == config_read_file(&cfg, configurationPath.c_str())) {
        config_destroy(&cfg);
        throw TcbError(configurationPath, "I/O error at config file",
                       CKR_GENERAL_ERROR);
    }

    root = config_root_setting(&cfg);
    dtc = config_setting_get_member(root, "libdtc");
    cryptoki = config_setting_get_member(root, "cryptoki");
    if(!cryptoki || !dtc) {
        config_destroy(&cfg);
        throw TcbError(configurationPath,
                       "cryptoki or libdtc configuration not found",
                       CKR_GENERAL_ERROR);
    }

    if(CONFIG_FALSE == config_setting_lookup_string(cryptoki, "dtc_config_path",
                                                    &aux_char)) {
        config_destroy(&cfg);
        throw TcbError(configurationPath, "dtc_config_path error",
                       CKR_GENERAL_ERROR);
    }
    dtcConfigPath_ = std::string(aux_char);

    if(CONFIG_FALSE == config_setting_lookup_string(cryptoki, "database_path",
                                                     &aux_char)) {
        config_destroy(&cfg);
        throw TcbError(configurationPath, "database_path error",
                       CKR_GENERAL_ERROR);
    }
    databasePath_ = std::string(aux_char);

    try {
        nodesNumber_ = lookupUint16Value(cryptoki, "nodes_number");
        threshold_ = lookupUint16Value(cryptoki, "threshold");
    } catch(const std::invalid_argument &e) {
        config_destroy(&cfg);
        throw TcbError(e.what(), "Not found.", CKR_GENERAL_ERROR);
    } catch(const std::overflow_error &e) {
        config_destroy(&cfg);
        throw TcbError(e.what(), "Not a valid value, must fit on uint16_t.",
                       CKR_GENERAL_ERROR);
    }

    if(!(slots = config_setting_get_member(cryptoki, "slots"))) {
        config_destroy(&cfg);
        throw TcbError("slots", "Not found", CKR_GENERAL_ERROR);
    }

    for(int i = 0; i < config_setting_length(slots); i++) {
        slot = config_setting_get_elem(slots, i);
        if(CONFIG_FALSE == config_setting_lookup_string(slot, "label",
                                                        &aux_char)) {
            config_destroy(&cfg);
            throw TcbError(std::to_string(i), "Not label at slot",
                            CKR_GENERAL_ERROR);
        }
        slotConf_.push_back({std::string(aux_char)});
    }

    /*
    databasePath_ = root.get<std::string>("database_path");

    //dtcConfigPath_ = root.get<std::string>("dtc_config_path");
    nodesNumber_ = root.get<uint16_t>("nodes_number");
    threshold_ = root.get<uint16_t>("threshold");
    //privateKey_(reinterpret_cast<const byte*>(str.data()), str.length());


    ptree slots = root.get_child("slots");
    for (ptree::value_type &v: slots) {
        ptree &token = v.second;
        slotConf_.push_back({token.get<string>("label")});
    }
    */

}

std::vector<Configuration::SlotConf> const &Configuration::getSlotConf() const {
    return slotConf_;
}

const std::string &Configuration::getDtcConfigPath() const {
    return dtcConfigPath_;
}

const uint16_t Configuration::getNodesNumber() const {
    return nodesNumber_;
}

const uint16_t Configuration::getThreshold() const {
    return threshold_;
}

const std::string &Configuration::getDatabasePath() const {
    fprintf(stderr, "Database:%s\n", databasePath_.c_str());
    return databasePath_;
}

//const std::string &Configuration::getPrivateKey() const {
//    return std::string s(reinterpret_cast<const char*>(privateKey_.begin()),
//                         privateKey_.size();)
//}
