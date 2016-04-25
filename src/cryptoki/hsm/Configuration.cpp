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
// strdup
#define _XOPEN_SOURCE 500

#include <cerrno>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string.h>

#include <libconfig.h>

#include "Configuration.h"
#include "TcbError.h"
#include "pkcs11.h"

using namespace hsm;

static uint16_t lookupUint16Value(config_setting_t *setting, const char *name) {
    long long aux_int64;
    if(CONFIG_FALSE == config_setting_lookup_int64(setting, name, &aux_int64)) {
        throw std::invalid_argument(name);
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
    config_setting_t *cryptoki, *dtc, *slots, *slot, *nodes, *node;
    const char *aux_char;
    int64_t aux_int64;
    struct node_info aux_node_info;

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

    // DTCLIB configuration
    if(CONFIG_FALSE == config_setting_lookup_string(dtc, "public_key",
                                                     &aux_char)) {
        config_destroy(&cfg);
        throw TcbError(configurationPath, "public_key error",
                       CKR_GENERAL_ERROR);
    }
    publicKey_ = std::string(aux_char);

    if(CONFIG_FALSE == config_setting_lookup_string(dtc, "instance_id",
                                                    &aux_char)) {
        config_destroy(&cfg);
        throw TcbError(configurationPath, "instance_id error",
                       CKR_GENERAL_ERROR);
    }
    instanceId_ = std::string(aux_char);

    try {
        timeout_ = lookupUint16Value(cryptoki, "timeout");
    } catch(const std::invalid_argument &e) {
        // TODO default is at libdtc level. Do we need a different default here?
        timeout_ = 10; // Default
    } catch(const std::overflow_error &e) {
        timeout_ = 10; // Default
    }

    if(CONFIG_FALSE == config_setting_lookup_string(dtc, "private_key",
                                                    &aux_char)) {
        config_destroy(&cfg);
        throw TcbError(configurationPath, "instance_id error",
                       CKR_GENERAL_ERROR);
    }
    privateKey_ = Botan::secure_vector<char>(
            aux_char, aux_char + strlen(aux_char));

    if(!(nodes = config_setting_get_member(dtc, "nodes"))) {
        config_destroy(&cfg);
        throw TcbError("nodes", "Not found", CKR_GENERAL_ERROR);
    }

    if(nodesNumber_ > config_setting_length(nodes)) {
        config_destroy(&cfg);
        throw TcbError(
                "PKCS11 is configured with an higher number of nodes than the ones provided.",
                CKR_GENERAL_ERROR);
    }

    for(int i = 0; i < config_setting_length(nodes); i++) {
        node = config_setting_get_elem(nodes, i);
        if(CONFIG_FALSE == config_setting_lookup_string(node, "ip",
                                                        &aux_char)) {
            config_destroy(&cfg);
            throw TcbError(std::to_string(i), "Node ip not found",
                           CKR_GENERAL_ERROR);
        }

        aux_node_info.ip = strdup(aux_char);

        if(CONFIG_FALSE == config_setting_lookup_string(node, "public_key",
                                                        &aux_char)) {
            config_destroy(&cfg);
            throw TcbError(std::to_string(i),
                           "Node public_key not found", CKR_GENERAL_ERROR);
        }
        aux_node_info.public_key = strdup(aux_char);

        try {
            aux_node_info.sub_port = lookupUint16Value(node, "sub_port");
            aux_node_info.dealer_port = lookupUint16Value(node, "dealer_port");
        } catch(const std::invalid_argument &e) {
            config_destroy(&cfg);
            throw TcbError(e.what(), "Not found at node.", CKR_GENERAL_ERROR);
        } catch(const std::overflow_error &e) {
            config_destroy(&cfg);
            throw TcbError(e.what(),
                           "Not a valid value at node, must fit on uint16_t.",
                           CKR_GENERAL_ERROR);
        }
        nodes_.push_back(aux_node_info);
    }
}

std::vector<Configuration::SlotConf> const &Configuration::getSlotConf() const {
    return slotConf_;
}

const std::string &Configuration::getDtcConfigPath() const {
    return dtcConfigPath_;
}

uint16_t Configuration::getNodesNumber() const {
    return nodesNumber_;
}

uint16_t Configuration::getThreshold() const {
    return threshold_;
}

const std::string &Configuration::getDatabasePath() const {
    return databasePath_;
}

std::unique_ptr<struct dtc_configuration> Configuration::getDtcConf() const {
    struct dtc_configuration *ptr = new struct dtc_configuration;
    std::unique_ptr<struct dtc_configuration> ret(ptr);
    if(!ret)
        return nullptr;
    ret->timeout = timeout_;
    ret->nodes_cant = nodesNumber_;
    ret->nodes = nodes_.data();
    ret->instance_id = instanceId_.data();
    ret->public_key = publicKey_.data();
    ret->private_key = privateKey_.data();

    return ret;
}

//const std::string &Configuration::getPrivateKey() const {
//    return std::string s(reinterpret_cast<const char*>(privateKey_.begin()),
//                         privateKey_.size();)
//}
