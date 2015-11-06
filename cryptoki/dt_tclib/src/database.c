#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//TODO do not use this anymore.
#include "database.h"
#include "blocking_sql3.h"
#include "err.h"
#include "logger/logger.h"
#include "utilities.h"

// DO NOT USE sqlite3_exec for USER PROVIDED queries/arguments.
#define START_MY_TEST(test_name) START_TEST(test_name)\
                                 LOG(LOG_LVL_LOG, "Testing: %s.", #test_name)
struct database_conn {
   sqlite3 *ppDb;
};

int sqlite3_my_blocking_exec(sqlite3 *db, const char *sql_query) {
    sqlite3_stmt *stmt;
    int rc, step;

    rc = sqlite3_blocking_prepare_v2(db, sql_query, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db));
        return DTC_ERR_DATABASE;
    }

    step = sqlite3_blocking_step(stmt);
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK)
        LOG(LOG_LVL_ERRO, "Error finalizing stmt: %s", sqlite3_errmsg(db));
    if(step == SQLITE_DONE)
        return DTC_ERR_NONE;
    LOG(LOG_LVL_ERRO, "Error blocking step: %s", sqlite3_errmsg(db));
    return DTC_ERR_DATABASE;
}

static int create_table(sqlite3 *db, const char *table_name,
                        const char *sql_creation_query) {
    int rc = sqlite3_my_blocking_exec(db, sql_creation_query);

    if(rc != DTC_ERR_NONE)
        LOG(LOG_LVL_ERRO, "Table %s couldn't be created:.\n%s", table_name,
            sql_creation_query);
    return rc;
}

static int create_tables(database_t *db) {
    unsigned int i;
    int rc;
    // TODO public_key also have to be NOT NULL
    const char *server_stmt =
                    "CREATE TABLE IF NOT EXISTS server (\n"\
                    "   server_id       TEXT PRIMARY KEY,\n"\
                    "   public_key      TEXT UNIQUE,\n"\
                    "   router_token    TEXT,\n"\
                    "   pub_token       TEXT\n"\
                    ");\n";
    const char *key_stmt =
                    "CREATE TABLE IF NOT EXISTS key (\n"
                    "   key_id          TEXT NOT NULL,\n"
                    "   server_id       TEXT NOT NULL,\n"
                    "   key_share       TEXT NOT NULL,\n"
                    "   key_metainfo    TEXT NOT NULL,\n"
                    "   PRIMARY KEY(server_id, key_id),\n"
                    "   FOREIGN KEY(server_id) REFERENCES server(server_id) "
                                                          "ON DELETE CASCADE"
                    ");\n";

    const char *new_server_stms =
                    "CREATE TABLE IF NOT EXISTS new_server (\n"\
                    "   server_id   TEXT PRIMARY KEY,\n"\
                    "   public_key  TEXT UNIQUE\n"\
                    ");";

    const char *tables[3][2] = {{"server", server_stmt},
                                {"key", key_stmt},
                                {"new_server", new_server_stms},
                               };

    for(i = 0; i < 3; i++) {
        rc = create_table(db->ppDb, tables[i][0], tables[i][1]);
        if(rc)
            return rc;
    }
    return DTC_ERR_NONE;
}

// Just works with const char *;
static int prepare_bind_stmt(sqlite3 *db, const char *query, sqlite3_stmt **out,
                             int args, ...) {
    unsigned i;
    int rc;
    sqlite3_stmt *stmt;

    rc = sqlite3_blocking_prepare_v2(db, query, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_prepare_v2: %s\n%s", sqlite3_errmsg(db),
            query);
        return DTC_ERR_DATABASE;
    }

    va_list valist;
    va_start(valist, args);

    for(i = 0; i < args; i++) {
        rc = sqlite3_bind_text(
                stmt, i + 1, va_arg(valist, const char *), -1, SQLITE_STATIC);
        if(rc != SQLITE_OK) {
            LOG(LOG_LVL_ERRO, "sqlite3_bind_text: %s", sqlite3_errmsg(db));
            break;
        }
    }

    va_end(valist);

    if(i != args) {
        sqlite3_finalize(stmt);
        return DTC_ERR_DATABASE;
    }

    *out = stmt;
    return DTC_ERR_NONE;
}


// API
database_t *db_init_connection(const char *path){
    int rc;
    char *err;
    database_t *ret = (database_t *) malloc(sizeof(database_t));
    static const char *foreign_keys_support = "PRAGMA foreign_keys = ON;";
    rc = sqlite3_open_v2(
            path, &ret->ppDb,
            SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
            NULL);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_CRIT, "Unable to open the database:%s",
            sqlite3_errstr(rc));
        sqlite3_close(ret->ppDb);
        free(ret);
        return NULL;
    }
    rc = sqlite3_exec(ret->ppDb, foreign_keys_support, NULL, NULL, &err);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_CRIT, "Foreign keys not supported:%s", err);
        sqlite3_free(err);
        db_close_and_free_connection(ret);
        return NULL;
    }
    rc = create_tables(ret);
    if(rc != DTC_ERR_NONE) {
        db_close_and_free_connection(ret);
        return NULL;
    }
    return ret;
}

void db_close_and_free_connection(database_t *db) {
    sqlite3_close(db->ppDb);
    free(db);
}

int db_add_new_server(database_t *db, const char *id, const char *public_key) {
    int rc, affected_rows, step;
    sqlite3_stmt *stmt = NULL;
    char *add_template  =
            "INSERT OR ABORT INTO new_server (server_id, public_key)\n"\
            "    VALUES(?, ?);";

    rc = prepare_bind_stmt(db->ppDb, add_template, &stmt, 2, id, public_key);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    sqlite3_finalize(stmt);
    if(step == SQLITE_DONE) {
        affected_rows = sqlite3_changes(db->ppDb);
        if(affected_rows != 1) {
            LOG(LOG_LVL_CRIT, "Add server affected %d rows instead of 1",
                affected_rows);
            return DTC_ERR_DATABASE;
        }
        return DTC_ERR_NONE;
    }
    else {
        LOG(LOG_LVL_ERRO, "Add new server failed: %s",
            sqlite3_errmsg(db->ppDb));
        return DTC_ERR_DATABASE;
    }
}

int db_update_servers(database_t *db) {
    int rc;
    static const char *delete =
        "DELETE\n"
        "FROM server\n"
        "WHERE server_id NOT IN\n"
        "   (SELECT server_id\n"
        "    FROM new_server\n"
        "    WHERE server.server_id = new_server.server_id);\n";

    static const char *update_existing =
        "UPDATE server\n"
        "SET public_key = (SELECT public_key\n"
        "                  FROM new_server\n"
        "                  WHERE server_id = server.server_id)\n"
        "WHERE server_id IN\n"
        "   (SELECT server_id\n"
        "    FROM new_server\n"
        "    WHERE (server_id = new_server.server_id and\n"
        "        public_key != server.public_key))\n";

    static const char *create_new =
        "INSERT INTO server(server_id, public_key)\n"
        "SELECT server_id, public_key\n"
        "FROM new_server\n"
        "WHERE server_id NOT IN (SELECT server_id FROM server);\n";

    static const char *delete_table =
        "DELETE FROM new_server";

    rc = create_tables(db);
    if(rc != DTC_ERR_NONE)
        return rc;

    // First, delete all servers not in new_servers.
    rc = sqlite3_my_blocking_exec(db->ppDb, delete);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error deleting server.");
        return rc;
    }
    LOG(LOG_LVL_LOG, "%d deleted servers on update.",
        sqlite3_changes(db->ppDb));

    // Then update existing.
    rc = sqlite3_my_blocking_exec(db->ppDb, update_existing);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error updating server.");
        return rc;
    }

    LOG(LOG_LVL_LOG, "%d servers were updated with a different public_key.",
        sqlite3_changes(db->ppDb));

    // And move the new servers from new_server to server.
    rc = sqlite3_my_blocking_exec(db->ppDb, create_new);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error inserting new servers.");
        return rc;
    }
    LOG(LOG_LVL_LOG, "%d new servers were added.", sqlite3_changes(db->ppDb));


    rc = sqlite3_my_blocking_exec(db->ppDb, delete_table);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error deleting new_server table.");
        return rc;
    }


    return DTC_ERR_NONE;
}

static int get_server_id(database_t *db, const char *sql_query, const char* key,
                         char **output) {
    int rc, step;
    const char *server_id;
    sqlite3_stmt *stmt = NULL;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, key);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        server_id = (const char *)sqlite3_column_text(stmt, 0);
    }
    else if(step == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    else {
        LOG(LOG_LVL_ERRO, "sqlite3_step: %s", sqlite3_errmsg(db->ppDb));
        sqlite3_finalize(stmt);
        return DTC_ERR_DATABASE;
    }

    *output = strdup((const char *)server_id);

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK)
        LOG(LOG_LVL_ERRO, "sqlite3_finalize %s", sqlite3_errmsg(db->ppDb));

    return DTC_ERR_NONE;

}

int db_get_key(database_t *db, const char *server_id, const char *key_id,
               char **key_share, char **key_metainfo)
{
    int rc, step;
    sqlite3_stmt *stmt = NULL;

    const char *sql_query = "SELECT key_share, key_metainfo\n"
                            "FROM key\n"
                            "WHERE key_id = ? and server_id = ?;";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, key_id, server_id);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        *key_share = strdup((const char *)sqlite3_column_text(stmt, 0));
        *key_metainfo = strdup((const char *)sqlite3_column_text(stmt, 1));
    }
    else if(step == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    else {
        LOG(LOG_LVL_ERRO, "sqlite3_step: %s", sqlite3_errmsg(db->ppDb));
        sqlite3_finalize(stmt);
        return DTC_ERR_DATABASE;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK)
        LOG(LOG_LVL_ERRO, "sqlite3_finalize %s", sqlite3_errmsg(db->ppDb));

    return DTC_ERR_NONE;
}

int db_get_server_id(database_t *db, const char *public_key, char **output) {
    static const char *sql_query = "SELECT server_id\n"
                                   "FROM server\n"
                                   "WHERE public_key = ?;";
    return get_server_id(db, sql_query, public_key, output);
}

int db_get_server_id_from_pub_token(database_t *db, const char *pub_token,
                                    char **output) {
    static const char *sql_query = "SELECT server_id\n"
                                   "FROM server\n"
                                   "WHERE pub_token = ?;";
    return get_server_id(db, sql_query, pub_token, output);
}

int db_get_server_id_from_router_token(database_t *db, const char *router_token,
                                       char **output){
    static const char *sql_query = "SELECT server_id\n"
                                   "FROM server\n"
                                   "WHERE router_token = ?;";
    return get_server_id(db, sql_query, router_token, output);
}

int db_is_key_id_available(database_t *db, const char *server_id,
                           const char *key_id) {
    sqlite3_stmt *stmt;
    int rc, step;
    char *sql_query = "SELECT server_id\n"
                      "FROM key\n"
                      "WHERE server_id = ? and key_id = ?;\n";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, server_id, key_id);
    if(rc != DTC_ERR_NONE)
        return 2;

    step = sqlite3_blocking_step(stmt);
    sqlite3_finalize(stmt);
    if(step == SQLITE_DONE) {
        return 1;
    }
    else if(step == SQLITE_ROW) {
        return 0;
    }
    LOG(LOG_LVL_ERRO, "Step db_is_key_id_available failed: %s",
        sqlite3_errmsg(db->ppDb));
    return 2;
}

static int db_get_current_token(database_t *db, const char *server_id,
                                const char *sql_query, char **output) {

    int rc, step;
    sqlite3_stmt *stmt = NULL;
    const char *token;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, server_id);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        token = (const char *)sqlite3_column_text(stmt, 0);
    }
    else if(step == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    else{
        LOG(LOG_LVL_ERRO, "sqlite3_step: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    *output = strdup((const char *)token);

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK)
        LOG(LOG_LVL_ERRO, "sqlite3_finalize: %s", sqlite3_errmsg(db->ppDb));

    return DTC_ERR_NONE;

err_exit:
    sqlite3_finalize(stmt);
    return DTC_ERR_DATABASE;
}

int db_get_router_token(database_t *db, const char *server_id, char **output) {
    return db_get_current_token(
            db, server_id, "SELECT router_token\n"
                           "FROM server\n"
                           "WHERE server_id= ?;\n", output);
}

int db_get_pub_token(database_t *db, const char *server_id, char **output) {
    return db_get_current_token(
            db, server_id, "SELECT pub_token\n"
                           "FROM server\n"
                           "WHERE server_id=?;\n", output);
}

int db_get_new_temp_token(database_t *db, const char *server_public_key,
                          const char *sql_query, char **output) {
    int rc, step, affected_rows;
    char token[37];
    sqlite3_stmt *stmt = NULL;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2,
                           get_uuid_as_char(&token[0]), server_public_key);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step != SQLITE_DONE) {
        LOG(LOG_LVL_ERRO, "Step error:%s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    affected_rows = sqlite3_changes(db->ppDb);
    if(affected_rows == 0) {
        sqlite3_finalize(stmt);
        LOG(LOG_LVL_WARN, "Trying to get new token for not authorized master");
        return -1;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed finalizing the statment: %s",
            sqlite3_errmsg(db->ppDb));

        return DTC_ERR_DATABASE;
    }

    *output = strdup(&token[0]);

    return DTC_ERR_NONE;

err_exit:
    sqlite3_finalize(stmt);
    return DTC_ERR_DATABASE;
}

int db_get_new_router_token(database_t *db, const char *server_public_key,
                            char **output) {
    return db_get_new_temp_token(
            db, server_public_key, "UPDATE server\n"
                                   "SET router_token = ?\n"
                                   "WHERE public_key = ?;", output);
}

int db_get_new_pub_token(database_t *db, const char *server_public_key,
                         char **output) {
    return db_get_new_temp_token(
            db, server_public_key, "UPDATE server\n"
                                   "SET pub_token = ?\n"
                                   "WHERE public_key = ?;", output);
}

int db_store_key(database_t *db, const char *server_id, const char *key_id,
                 const char *metainfo, const char *key_share) {

    int rc, step, affected_rows;
    sqlite3_stmt *stmt;
    char *sql_query  = "INSERT INTO key "
                       "(server_id, key_id, key_metainfo, key_share)\n"
                       "VALUES (?, ?, ?, ?);";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 4, server_id, key_id,
                           metainfo, key_share);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step != SQLITE_DONE) {
        LOG(LOG_LVL_ERRO, "Step error:%s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    affected_rows = sqlite3_changes(db->ppDb);
    if(affected_rows != 1) {
        sqlite3_finalize(stmt);
        LOG(LOG_LVL_ERRO, "Key %s from server %s couldn't be inserted.", key_id,
            server_id);
        return DTC_ERR_DATABASE;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed finalizing the statment: %s",
            sqlite3_errmsg(db->ppDb));
        return DTC_ERR_DATABASE;
    }

    return DTC_ERR_NONE;

err_exit:
    sqlite3_finalize(stmt);
    return DTC_ERR_DATABASE;
}


int db_is_an_authorized_key(database_t *db, const char *key) {
    int rc, step;
    sqlite3_stmt *stmt = NULL;
    static const char *sql_query = "SELECT server_id\n"
                                   "FROM server\n"
                                   "WHERE public_key=?;";
    //TODO use the prepare wrapper.
    rc = sqlite3_blocking_prepare_v2(db->ppDb, sql_query, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    rc = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_bind_text: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return 1;
    }
    else if(step == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return 0;
    }
    else{
        LOG(LOG_LVL_ERRO, "sqlite3_step: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

err_exit:
    sqlite3_finalize(stmt);
    return -1;
}

int db_delete_key(database_t *db, const char *server_id, const char *key_id){
    int rc, step, affected_rows;
    sqlite3_stmt *stmt = NULL;
    static const char *sql_query = "DELETE\n"
                                   "FROM key\n"
                                   "WHERE server_id = ? and key_id = ?;";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, server_id, key_id);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step != SQLITE_DONE) {
        LOG(LOG_LVL_ERRO, "Step error:%s", sqlite3_errmsg(db->ppDb));
        sqlite3_finalize(stmt);
        return DTC_ERR_DATABASE;
    }

    affected_rows = sqlite3_changes(db->ppDb);
    if(affected_rows != 1) {
        sqlite3_finalize(stmt);
        LOG(LOG_LVL_ERRO, "Tried to delete a unexistent key, %s:%s",
            server_id, key_id);
        return -1;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed finalizing the statment: %s",
            sqlite3_errmsg(db->ppDb));
        return DTC_ERR_DATABASE;
    }

    return DTC_ERR_NONE;
}

#ifdef UNIT_TEST

#include <unistd.h>

// TODO IF a test fails the file might remain in the temp folder, we need to
// change this kind of check or figure out some way to do a clean up.

static char *get_filepath(const char *file) {

    const char *testing_dir = "/tmp/";
    size_t total_size = strlen(testing_dir) + strlen(file) + 1;
    size_t printed;
    char *ret = (char *) malloc(sizeof(char) * total_size);
    if(!ret)
        return ret;
    printed = snprintf(ret, total_size, "%s%s", testing_dir, file);
    if(printed >= total_size){
        free(ret);
        return NULL;
    }
    return ret;
}

static void close_and_remove_db(char *file, database_t *db) {
    db_close_and_free_connection(db);
    ck_assert_int_eq(0, remove(file));
    free(file);
}

// Testing only, do not use it, it allows SQL injection.
static int insert_server(sqlite3 *db, const char *server_key,
                         const char *server_id, const char *token) {
    char *err;
    size_t ret;
    int rc;
    char *sql_template  = "INSERT INTO server (public_key, server_id, "
                                              "router_token, pub_token)\n"
                          "    VALUES('%s', '%s', '%s', '%s');";
    size_t len = strlen(sql_template) +
                 strlen(server_key) +
                 strlen(server_id) +
                 strlen(token) +
                 strlen(token) + 1; // %s will be replaced, this isn't needed.
    char *sql_query = (char *) malloc(sizeof(char) * len);
    ret = snprintf(sql_query, len, sql_template, server_key, server_id, token,
                   token);
    ck_assert(ret < len);

    rc = sqlite3_exec(db, sql_query, NULL, NULL, &err);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Error inserting server: %s\n%s", err, sql_query);
        sqlite3_free(err);
        free(sql_query);
        return DTC_ERR_DATABASE;
    }

    free(sql_query);

    return DTC_ERR_NONE;

}

START_MY_TEST(test_create_db) {
    char *database_file = get_filepath("test_create_db");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, access(database_file, F_OK));

    close_and_remove_db(database_file, conn);

}
END_TEST

static int foreign_key_callback(void * unused, int cols, char **cols_data,
                                char **cols_name) {
    ck_assert_int_eq(1, cols);
    ck_assert_str_eq("1", cols_data[0]);

    return 0;
}

START_MY_TEST(test_foreign_keys_support) {
    char *database_file = get_filepath("test_foreign_keys_support");
    int rc;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    rc = sqlite3_exec(conn->ppDb, "PRAGMA foreign_keys;", foreign_key_callback,
                      NULL, NULL);
    ck_assert_int_eq(SQLITE_OK, rc);

    close_and_remove_db(database_file, conn);

}
END_TEST

START_MY_TEST(test_create_tables) {
    char *database_file = get_filepath("test_create_tables");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));

    ck_assert_int_eq(0, access(database_file, F_OK));

    close_and_remove_db(database_file, conn);

}
END_TEST

START_MY_TEST(test_get_new_token_empty_db) {
    char *result;
    const char *server_p_key = "a98478teqgdkg129*&&%^$%#$";
    char *database_file = get_filepath("test_get_new_token_empty_db");
    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ck_assert_int_eq(-1,
                     db_get_new_router_token(conn, server_p_key, &result));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_get_new_token_server_not_found) {
    char *database_file = get_filepath("test_get_new_token_server_not_found");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));

    ck_assert_int_eq(-1, db_get_new_pub_token(conn, "any_key", NULL));

    close_and_remove_db(database_file, conn);

}
END_TEST

START_MY_TEST(test_get_new_token_consistency) {

    char *database_file = get_filepath("test_get_new_token_consistency");
    char *server_key = "1(*A&S^DYHJA]&TYHJ@aklut*&@2128ha";
    char *old_token = "no_token";
    char *server_id = "server_id";
    char *current_token = NULL;
    char *result;

    ck_assert_int_eq(-1, access(database_file, F_OK));
    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));

    ck_assert_int_eq(DTC_ERR_NONE,
                     insert_server(conn->ppDb, server_key, server_id,
                                   old_token));
    ck_assert_int_eq(DTC_ERR_NONE,
                     insert_server(conn->ppDb, "other_key", "rand_id",
                                   "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                    db_get_new_router_token(conn, server_key, &result));
    free((void *)result);

    // Check changed token.
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_get_router_token(conn, server_id, &current_token));
    ck_assert_str_ne(old_token, current_token);
    ck_assert_str_ne("token", current_token);
    free(current_token);

    //Check not changed token
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_get_router_token(conn, "rand_id", &current_token));
    ck_assert_str_eq("token", current_token);
    free(current_token);

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_db_is_an_authorized_key_empty_db) {

    char *database_file = get_filepath("test_db_is_an_authorized_key_empty_db");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ck_assert_int_eq(0, db_is_an_authorized_key(conn, "any_key"));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_db_is_an_authorized_key) {

    char *database_file = get_filepath("test_db_is_an_authorized_key");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));
    ck_assert_int_eq(DTC_ERR_NONE,
                     insert_server(conn->ppDb, "valid_key", "id", "token"));

    ck_assert_int_eq(1, db_is_an_authorized_key(conn, "valid_key"));
    ck_assert_int_eq(0, db_is_an_authorized_key(conn, "not_valid_key"));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_db_add_new_server) {
    char *database_file = get_filepath("test_db_add_new_server");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id_1", "key_1"));
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_add_new_server(conn, "id_1", "key_3"));
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_add_new_server(conn, "id_n", "key_1"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id_n", "key_n"));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_servers_empty_db) {
    char *database_file = get_filepath("test_update_server_empty_tables");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, db_update_servers(conn));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_servers_no_old_servers) {
    char *aux;
    char *database_file = get_filepath("test_update_servers_no_old_servers");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id", "key"));
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_add_new_server(conn, "id", "key_2"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id_2", "key_2"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_servers(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "key", &aux));
    ck_assert_str_eq("id", aux);
    free(aux);

    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "key_2", &aux));
    ck_assert_str_eq("id_2", aux);
    free(aux);
    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_servers_update_only) {
    char *aux;
    char *database_file = get_filepath("test_update_servers_update_only");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id", "key2"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_servers(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "key2", &aux));
    ck_assert_str_eq("id", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_servers_replace) {
    char *aux;
    char *database_file = get_filepath("test_update_servers_replace");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id2", "key"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_servers(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "key", &aux));
    ck_assert_str_eq("id2", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_servers_nothing_to_update) {
    char *aux;
    char *database_file = get_filepath("test_update_servers_nothing_to_update");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id", "key"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_servers(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "key", &aux));
    ck_assert_str_eq("id", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST
START_MY_TEST(test_update_servers_delete_only) {
    char *aux;
    char *database_file = get_filepath("test_update_servers_delete_only");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "id", "token"));
    ck_assert_int_eq(0, insert_server(conn->ppDb, "key2", "id2", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_servers(conn));


    ck_assert_int_eq(-1, db_get_server_id(conn, "key", &aux));
    ck_assert_int_eq(-1, db_get_server_id(conn, "key2", &aux));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_servers_mix_operations) {
    char *aux;
    char *database_file = get_filepath("test_update_servers_just_update");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "id", "token"));
    ck_assert_int_eq(0, insert_server(conn->ppDb, "key2", "id2", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id2", "updatedkey2"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_server(conn, "id3", "key3"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_servers(conn));


    ck_assert_int_eq(-1, db_get_server_id(conn, "key", &aux));
    ck_assert_int_eq(-1, db_get_server_id(conn, "key2", &aux));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "updatedkey2", &aux));
    ck_assert_str_eq("id2", aux);
    free(aux);

    ck_assert_int_eq(DTC_ERR_NONE, db_get_server_id(conn, "key3", &aux));
    ck_assert_str_eq("id3", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST

static int get_keys_callback(void *expected_keys, int cols, char **cols_data,
                             char **cols_name) {
    char **keys = (char **)expected_keys;
    char *expected_metainfo = keys[0];
    char *expected_key_share = keys[1];
    ck_assert_ptr_ne(NULL, *keys);

    ck_assert_int_eq(2, cols);
    ck_assert_str_eq(expected_metainfo, cols_data[0]);
    ck_assert_str_eq(expected_key_share, cols_data[1]);

    // This limit the times the callback can be called to 1.
    *keys = NULL;

    return 0;
}

START_MY_TEST(test_store_key_simple) {
    char *database_file = get_filepath("test_store_key_simple");
    char *keys[2];
    int rc;

    keys[0] = "key_metainfo_";
    keys[1] = "k_share_";

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "s_id", "token"));
    //ck_assert_int_eq(0, insert_server(conn->ppDb, "key2", "s_id2", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s_id", "k_id", keys[0], keys[1]));
    rc = sqlite3_exec(conn->ppDb, "SELECT key_metainfo, key_share\n"
                                  "FROM key\n"
                                  "WHERE server_id = 's_id' and "
                                    "key_id = 'k_id';\n",
                      get_keys_callback, &keys, NULL);

    ck_assert_int_eq(SQLITE_OK, rc);
    // This check that the callback was called.
    ck_assert_ptr_eq(NULL, *keys);

    keys[0] = "key_metainfo_";
    keys[1] = "k_share_";
    ck_assert_int_eq(0, insert_server(conn->ppDb, "key2", "s2_id", "token"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s2_id", "k_id", keys[0], keys[1]));
    ck_assert_int_ne(DTC_ERR_NONE,
                     db_store_key(conn, "s2_id", "k_id", keys[0], keys[1]));

    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_store_key(conn, "s2_id", "k_id", keys[0], "diff"));
    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_get_key) {
    char *database_file = get_filepath("test_get_key");
    char *keys[2][2];
    char *key_share, *key_metainfo;

    keys[0][0] = "key_metainfo_";
    keys[0][1] = "key_share";

    keys[1][0] = "metainfo_";
    keys[1][1] = "share";

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key" ,"s_id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s_id", "k_1", keys[0][0], keys[0][1]));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s_id", "k_2", keys[1][0], keys[1][1]));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_get_key(conn, "s_id", "k_1", &key_share,
                                &key_metainfo));

    ck_assert_int_eq(-1,
                     db_get_key(conn, "s_id", "k_3", NULL, NULL));

    ck_assert_str_eq(keys[0][0], key_metainfo);
    ck_assert_str_eq(keys[0][1], key_share);
    free(key_share);
    free(key_metainfo);
    close_and_remove_db(database_file, conn);
}
END_TEST

START_TEST(test_delete_key_simple) {
    char *database_file = get_filepath("test_store_key_simple");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, insert_server(conn->ppDb, "key", "s_id", "token"));

    ck_assert_int_eq(-1,
                     db_delete_key(conn, "s_id", "k_id"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s_id", "k_id", "k_1", "k_2"));
    ck_assert_int_eq(0,
                     db_delete_key(conn, "s_id", "k_id"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s_id", "k_id", "k_1", "k_2"));

    close_and_remove_db(database_file, conn);
}
END_TEST

TCase *get_dt_tclib_database_c_test_case() {

    TCase *test_case = tcase_create("database_c");

    tcase_add_test(test_case, test_foreign_keys_support);

    tcase_add_test(test_case, test_create_db);
    tcase_add_test(test_case, test_create_tables);
    //printf("%p\n%p\n", test_get_new_token_empty_db, test_get_new_token_server_not_found);

    tcase_add_test(test_case, test_get_new_token_empty_db);
    tcase_add_test(test_case, test_get_new_token_server_not_found);
    tcase_add_test(test_case, test_get_new_token_consistency);

    tcase_add_test(test_case, test_db_is_an_authorized_key_empty_db);
    tcase_add_test(test_case, test_db_is_an_authorized_key);

    tcase_add_test(test_case, test_db_add_new_server);

    tcase_add_test(test_case, test_update_servers_empty_db);
    tcase_add_test(test_case, test_update_servers_no_old_servers);
    tcase_add_test(test_case, test_update_servers_update_only);
    tcase_add_test(test_case, test_update_servers_nothing_to_update);
    tcase_add_test(test_case, test_update_servers_replace);
    tcase_add_test(test_case, test_update_servers_delete_only);
    tcase_add_test(test_case, test_update_servers_mix_operations);

    tcase_add_test(test_case, test_store_key_simple);

    tcase_add_test(test_case, test_get_key);

    tcase_add_test(test_case, test_delete_key_simple);

    return test_case;
}

#endif
