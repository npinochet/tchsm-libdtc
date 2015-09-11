//#include <cstring>

//#include <Token.h>
//#include "CryptoObject.h"
#include <stdlib.h>
#include "database.h"
#include "logger/logger.h"

//#include "TcbError.h"

struct database_conn {
   sqlite3 *ppDb;
};

database_t *db_init_connection(const char *path){
    int rc;
    database_t *ret = (database_t *) malloc(sizeof(database_t));
    rc = sqlite3_open(path, &ret->ppDb);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_CRIT, "Unable to open the database:%s",
            sqlite3_errstr(rc));
        sqlite3_close(ret);
        return NULL;
    }
    return ret;
}

void db_close_and_free_connection(database_t *db) {
    sqlite3_close(db->ppDb);
    free(db);
}

static int create_tables(database_t *db) {
    const char *server_stmt =
                    "CREATE TABLE IF NOT EXISTS server ( "\
                    "   server_id   TEXT PRIMARY KEY, "\
                    "   public_key  TEXT, NOT NULL" \
                    "   last_token  TEXT
                    ");";
    const char *key_share_stmt =
                    "CREATE TABLE IF NOT EXISTS key_share ( "\
                    "   server_id   TEXT PRIMARY KEY, "\
                    "   key_id      TEXT TEXT PRIMARY KEY, "\
                    "   key         TEXT, "\
                    "   n           TEXT, "\
                    "   id          INTEGER, "\
                    "   FOREIGN KEY(server_id) REFERENCES server "\
                    ");";
    const char *public_key_stmt =
                    "CREATE TABLE IF NOT EXISTS public_key ( "\
                    "   server_id   TEXT PRIMARY KEY, "\
                    "   key_id      TEXT PRIMARY KEY, "\
                    "   n           TEXT, "\
                    "   m           TEXT, "\
                    "   e           TEXT, "\
                    "   FOREIGN KEY(server_id, key_id) REFERENCES key_share) "\
                    ");";
    const char *key_metainfo_stmt =
                    "CREATE TABLE IF NOT EXISTS key_metainfo ( "\
                    "   server_id   TEXT PRIMARY KEY, "\
                    "   key_id      TEXT PRIMARY KEY, "\
                    "   bit_size    INTEGER, "\
                    "   k           INTEGER, "\
                    "   l           INTEGER, "\
                    "   vk_v        TEXT, "\
                    "   vk_id       INTEGER, "\
                    "   FOREIGN KEY(server_id, key_id) REFERENCES key_share "\
                    ");";
    const char *verification_key_stms =
                    "CREATE TABLE IF NOT EXISTS verification_key ( "\
                    "   id          INTEGER PRIMARY KEY, "\
                    "   vk          TEXT PRIMARY KEY, "\
                    ");";

    const char *tables[2][2] = {{"server", server_stmt},
                                {"key_share", key_share_stmt}
                               };
    printf("%s", tables[1][1]);
    return 0;
}

#ifdef UNIT_TEST

char *testing_dir = "/tmp/"

START_TEST(test_create_tables) {

}
