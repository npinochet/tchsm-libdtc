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

#include <fstream>
#include <cerrno>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "Configuration.h"
#include "TcbError.h"
#include "pkcs11.h"

using namespace hsm;

Configuration::Configuration(std::string configurationPath) {
    this->Configuration::load(configurationPath);
}

void Configuration::load(std::string configurationPath) {
    using std::string;
    using boost::property_tree::ptree;
    using namespace boost::property_tree::json_parser;
    ptree root;

    try {
        read_json(configurationPath, root);
    } catch (json_parser_error &e) {
        throw TcbError("Configuration::load", e.what(), CKR_GENERAL_ERROR);
    }

    databasePath_ = root.get<std::string>("database_path");

    dtcConfigPath_ = root.get<std::string>("dtc_config_path");
    nodesNumber_ = root.get<uint16_t>("nodes_number");
    threshold_ = root.get<uint16_t>("threshold");


    ptree slots = root.get_child("slots");
    for (ptree::value_type &v: slots) {
        ptree &token = v.second;
        slotConf_.push_back({token.get<string>("label")});
    }

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
    return databasePath_;
}
