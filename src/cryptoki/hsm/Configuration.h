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

#ifndef TCBHSM_CONFIGURATION_H
#define TCBHSM_CONFIGURATION_H

#include <string>
#include <vector>

#include <dtc.h>

namespace hsm
{
class Configuration
{
public:
    struct SlotConf {
        std::string label;
    };


    Configuration() = default;
    Configuration ( std::string configurationPath );
    Configuration ( Configuration const & ) = default;
    Configuration ( Configuration && ) = default;
    Configuration & operator=(Configuration const &) = default;
    Configuration & operator=(Configuration &&) = default;

    std::vector<SlotConf> const & getSlotConf() const;
    const std::string & getDtcConfigPath() const;
    const uint16_t getNodesNumber() const;
    const uint16_t getThreshold() const;
    const std::string & getDatabasePath() const;
    void load(std::string configurationPath);

    ~Configuration() = default;
private:
    std::vector<SlotConf> slotConf_;
    std::string dtcConfigPath_;
    std::string databasePath_;
    std::vector<node_info> nodes_;
    //SecureVector<byte> privateKey_;
    //std::string

    uint16_t nodesNumber_;
    uint16_t threshold_;

};
}

#endif // TCBHSM_CONFIGURATION_H
