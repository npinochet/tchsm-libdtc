#ifndef DT_TCLIB_DTC_H_
#define DT_TCLIB_DTC_H_

#include <sqlite3.h>

struct database_conn;
typedef struct database_conn database_t;


database_t *db_init_connection(const char *path);

void db_close_and_free_connection(database_t *db);

// sqlite3 serializer
/*
namespace hsm {

class Database : public hsm::TokenSerializer
{
    // TODO: GET MAX CRYPTO OBJECT ID
    sqlite3 * db_;
    void init(std::string path);

public:
    Database(std::string path);
    Database() = default;
    virtual ~Database();
    Database(Database const &) = delete;
    Database(Database &&);
    Database & operator=(Database const &) = delete;
    Database & operator=(Database &&);


    virtual hsm::Token* getToken(std::string label);
    virtual void saveToken(hsm::Token& token);
    virtual void saveCryptoObject(Token& token, CryptoObject& object);
};
}
*/
#endif // DT_TCLIB_DTC_H_
