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

#include <cstring>
#include <cstdlib>

#include <Token.h>
#include "CryptoObject.h"
#include "Database.h"
#include "TcbError.h"

using namespace hsm;
using std::malloc;

namespace {
    char const *GET_TOKEN_QUERY = "SELECT TKN_PIN, TKN_SO_PIN "
            "FROM TOKEN "
            "WHERE TKN_LABEL = ?";

    char const *GET_MAX_CO_QUERY = "SELECT MAX(CO_HANDLE) FROM CRYPTO_OBJECT";

    char const *GET_ATTS_QUERY = "SELECT CO.CO_HANDLE, ATT.ATT_TYPE, ATT.ATT_VALUE "
            "FROM CRYPTO_OBJECT AS CO NATURAL JOIN ATTRIBUTE AS ATT "
            "WHERE CO.TKN_LABEL = ?";

    char const *INSERT_TOKEN_QUERY = "INSERT OR IGNORE INTO TOKEN (TKN_LABEL, TKN_PIN, TKN_SO_PIN) VALUES (?, ?, ?)";
    char const *INSERT_CO_QUERY = "INSERT OR IGNORE INTO CRYPTO_OBJECT (TKN_LABEL, CO_HANDLE) VALUES (?, ?)";
    char const *INSERT_ATTRIBUTE_QUERY = "INSERT OR REPLACE INTO ATTRIBUTE (TKN_LABEL, CO_HANDLE, ATT_TYPE, ATT_VALUE) VALUES (?,?,?,?)";

    char const *CLEAN_ATTRIBUTES_QUERY = "DELETE FROM ATTRIBUTE WHERE TKN_LABEL=?";

}

Database::Database(std::string path) {
    init(path);
}

Database::Database(Database &&db) {
    std::swap(db_, db.db_);
}

Database &Database::operator=(Database &&db) {
    std::swap(db_, db.db_);
    return *this;
}

Database::~Database() {
    sqlite3_close(db_);
}

void Database::create_cryptoki_tables(sqlite3 *db_) {
    unsigned int i;

    const char *token_stmt =
            "CREATE TABLE IF NOT EXISTS TOKEN (\n"\
            "   TKN_LABEL    PRIMARY KEY,\n"\
            "   TKN_PIN      TEXT,\n"\
            "   TKN_SO_PIN   TEXT\n"\
            ");\n";
    const char *crypto_object_stmt =
            "CREATE TABLE IF NOT EXISTS CRYPTO_OBJECT (\n"\
            "   TKN_LABEL    TEXT,\n"\
            "   CO_HANDLE    INTEGER,\n"\
            "   PRIMARY KEY  (TKN_LABEL, CO_HANDLE)\n"\
            ");\n";
    const char *attribute_stmt =
            "CREATE TABLE IF NOT EXISTS ATTRIBUTE (\n"\
            "   TKN_LABEL    TEXT,\n"\
            "   CO_HANDLE    INTEGER,\n"\
            "   ATT_TYPE     INTEGER,\n"\
            "   ATT_VALUE    BLOB,\n"\
            "   PRIMARY KEY  (TKN_LABEL, CO_HANDLE, ATT_TYPE)\n"\
            ");\n";

    const char *tables[3][2] = {{"token", token_stmt},
                                {"crypto_object", crypto_object_stmt},
                                {"attribute", attribute_stmt}
    };

    int rc;
    for(i = 0; i < 3; i++) {
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(db_, tables[i][1], std::string(tables[i][1]).size(), &stmt, nullptr);

        if(rc != SQLITE_OK) {
            sqlite3_close(db_);
            throw TcbError("Database::create_cryptoki_tables", "Couldn't prepare statements", CKR_GENERAL_ERROR);
        }

        int step;
        step = sqlite3_step(stmt);
        rc = sqlite3_finalize(stmt);
        if (rc != SQLITE_OK) {
            sqlite3_close(db_);
            throw TcbError("Database::create_cryptoki_tables", "Couldn't finalize statements", CKR_GENERAL_ERROR);
        }
        if(step != SQLITE_DONE) {
            sqlite3_close(db_);
            throw TcbError("Database::create_cryptoki_tables", "Error blocking step", CKR_GENERAL_ERROR);
        }
    }
}

void Database::insert_token(sqlite3 *db_) {
    int rc, step;

    const char *token_insertion_stmt =
            "INSERT INTO TOKEN VALUES (\"TCBHSM\", \"1234\", \"1234\");";

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db_, token_insertion_stmt, std::string(token_insertion_stmt).size(), &stmt, nullptr);

    if(rc != SQLITE_OK) {
        sqlite3_close(db_);
        throw TcbError("Database::insert_token", "Couldn't prepare statement", CKR_GENERAL_ERROR);
    }

    step = sqlite3_step(stmt);
    rc = sqlite3_finalize(stmt);

    if (rc != SQLITE_OK && rc != SQLITE_CONSTRAINT) {
        sqlite3_close(db_);
        throw TcbError("Database::insert_token", "Couldn't finalize statement", CKR_GENERAL_ERROR);
    }
    if(step != SQLITE_DONE && rc != SQLITE_CONSTRAINT) {
        sqlite3_close(db_);
        throw TcbError("Database::insert_token", "Error blocking step", CKR_GENERAL_ERROR);
    }
}

void Database::assign_crypto_object_handle(sqlite3 *pSqlite3) {
    //int step;
    int rc;

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db_, GET_MAX_CO_QUERY, std::string(GET_MAX_CO_QUERY).size(), &stmt, nullptr);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CryptoObject::actualHandle = sqlite3_column_int(stmt, 0);
    } else {
        sqlite3_finalize(stmt);
        throw TcbError("Database::assign_crypto_object_handle", "Cannot get max handle", CKR_GENERAL_ERROR);
    }
    sqlite3_finalize(stmt);
}

void Database::init(std::string path) {
    int rc;
    rc = sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);

    if (rc != SQLITE_OK) {
        sqlite3_close(db_);
        throw TcbError("Database::init", "Couldn't open database", CKR_GENERAL_ERROR);
    }

    create_cryptoki_tables(db_);
    insert_token(db_);
    assign_crypto_object_handle(db_);
}

hsm::Token *Database::getToken(std::string label) {
    using std::string;
    using AttributesMap = std::unordered_map<CK_SESSION_HANDLE, std::vector<CK_ATTRIBUTE>>;

    Token *token;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db_, GET_TOKEN_QUERY, std::string(GET_TOKEN_QUERY).size(), &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, label.c_str(), label.size(), SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        string pin(reinterpret_cast<char const *>(sqlite3_column_text(stmt, 0)));
        string so_pin(reinterpret_cast<char const *>(sqlite3_column_text(stmt, 1)));
        token = new Token(label, pin, so_pin);
    } else {
        sqlite3_finalize(stmt);
        throw TcbError("Database::getToken", "Cannot get token from database", CKR_GENERAL_ERROR);
    }
    sqlite3_finalize(stmt);


    sqlite3_prepare_v2(db_, GET_ATTS_QUERY, std::string(GET_ATTS_QUERY).size(), &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, label.c_str(), label.size(), SQLITE_STATIC);

    AttributesMap attributesMap;

    std::vector<CK_ATTRIBUTE> attributes;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CK_SESSION_HANDLE handle = sqlite3_column_int(stmt, 0);
        CK_ATTRIBUTE attribute;
        attribute.type = sqlite3_column_int(stmt, 1);

        const void *blob = sqlite3_column_blob(stmt, 2);
        attribute.ulValueLen = sqlite3_column_bytes(stmt, 2);

        attribute.pValue = malloc(attribute.ulValueLen); // to be freed on CryptoObject's destructor
        std::memcpy(attribute.pValue, blob, attribute.ulValueLen);

        attributesMap[handle].push_back(attribute);
    }

    sqlite3_finalize(stmt);

    for (AttributesMap::value_type const &pair: attributesMap) {
        CryptoObject *cryptoObject = new CryptoObject(pair.first, pair.second);
        token->addObject(cryptoObject);
    }

    return token;
}

void Database::saveToken(hsm::Token &token) {
    sqlite3_stmt *insertCryptoObjectStmt;
    sqlite3_stmt *cleanAttributesStmt;
    sqlite3_stmt *insertAttributesStmt;

    sqlite3_prepare_v2(db_, INSERT_CO_QUERY, std::string(INSERT_CO_QUERY).size(), &insertCryptoObjectStmt, nullptr);
    sqlite3_prepare_v2(db_, CLEAN_ATTRIBUTES_QUERY, std::string(CLEAN_ATTRIBUTES_QUERY).size(), &cleanAttributesStmt,
                       nullptr);
    sqlite3_prepare_v2(db_, INSERT_ATTRIBUTE_QUERY, std::string(INSERT_ATTRIBUTE_QUERY).size(), &insertAttributesStmt,
                       nullptr);

    std::string label(token.getLabel());

    sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
    // clean previously stored attributes...
    sqlite3_bind_text(cleanAttributesStmt, 1, label.c_str(), label.size(), SQLITE_STATIC);
    sqlite3_step(cleanAttributesStmt); // TODO: Verify for errors...
    sqlite3_reset(cleanAttributesStmt);

    for (auto &pair : token.getObjects()) {
        CK_OBJECT_HANDLE handle = pair.first;

        // insert if not exists
        sqlite3_bind_text(insertCryptoObjectStmt, 1, label.c_str(), label.size(), SQLITE_STATIC);
        sqlite3_bind_int(insertCryptoObjectStmt, 2, handle);
        sqlite3_step(insertCryptoObjectStmt); // TODO: Verify for errors...
        sqlite3_reset(insertCryptoObjectStmt);

        for (auto const &attributePair : pair.second->getAttributes()) {
            CK_ATTRIBUTE_TYPE type = attributePair.first;
            CK_ATTRIBUTE const &attribute = attributePair.second;

            sqlite3_bind_text(insertAttributesStmt, 1, label.c_str(), label.size(), SQLITE_STATIC);
            sqlite3_bind_int(insertAttributesStmt, 2, handle);
            sqlite3_bind_int(insertAttributesStmt, 3, type);
            sqlite3_bind_blob(insertAttributesStmt, 4, attribute.pValue, attribute.ulValueLen, SQLITE_STATIC);
            sqlite3_step(insertAttributesStmt); // TODO: Verify for errors...
            sqlite3_reset(insertAttributesStmt);
        }
    }
    sqlite3_exec(db_, "END TRANSACTION", nullptr, nullptr, nullptr);
    sqlite3_finalize(insertCryptoObjectStmt);
    sqlite3_finalize(cleanAttributesStmt);
    sqlite3_finalize(insertAttributesStmt);
}





