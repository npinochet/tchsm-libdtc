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

#include <libconfig.h++>

#include "Configuration.h"
#include "TcbError.h"
#include "pkcs11.h"

using namespace hsm;
using namespace libconfig;

Configuration::Configuration(std::string configurationPath) {
    this->Configuration::load(configurationPath);
}

void Configuration::load(std::string configurationPath) {
    Config cfg;
    Setting cryptoki_settings, dtc_settings;

    try {
        cfg.readFile(configurationPath, root);
    } catch(const FileIOException &e) {
        throw TcbError(configurationPath, "I/O error while reading config file",
                       CKR_GENERAL_ERROR);
    } catch(const ParseException &pex) {
        std::stringstream ss;
        ss << "Parse error at " << pex.getFile() << ":" << pex.getLine()
           << " - " << pex.getError();
        throw TcbError(ss.str(), CKR_GENERAL_ERROR);
    }

    try {
        cryptoki_settings = cfg.lookup("cryptoki");
        dtc_settings = cfg.lookup("libdtc");

    } catch(const SettingNotFoundException &snf) {
        throw TcbError(configurationPath, "TODO", CKR_GENERAL_ERROR);
    }

    try {
        nodesNumber_ = cryptoki_settings["nodes_number"];
        threshold_ = cryptoki_settings["threshold"];
        dtcConfigPath_ = cryptoki_settings["dtc_config_path"];

        const Setting slots = cryptoki_settings['slots'];
        int num_slots = slots.getLength();

        for(int i = 0; i < num_slots; i++) {
            const Setting &slot = slots[i];
            slotConf_.push_back({slot["label"]});
        }



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
    return std::string("ASDASD");
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

//const std::string &Configuration::getPrivateKey() const {
//    return std::string s(reinterpret_cast<const char*>(privateKey_.begin()),
//                         privateKey_.size();)
//}
