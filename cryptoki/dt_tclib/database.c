#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "database.h"
#include "err.h"
#include "logger/logger.h"


struct database_conn {
   sqlite3 *ppDb;
};

// Helpers
static int create_table(sqlite3 *db, const char *table_name,
                        const char *sql_creation_query) {
    char *err;
    int rc = sqlite3_exec(db, sql_creation_query, NULL, NULL, &err);

    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Table %s couldn't be created: %s.\n%s", table_name,
            err, sql_creation_query);
        sqlite3_free(err);
        return DTC_ERR_DATABASE;
    }

    return DTC_ERR_NONE;
}

static char *generate_token(char *ret) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, ret);

    return ret;
}

// API
database_t *db_init_connection(const char *path){
    int rc;
    database_t *ret = (database_t *) malloc(sizeof(database_t));
    rc = sqlite3_open(path, &ret->ppDb);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_CRIT, "Unable to open the database:%s",
            sqlite3_errstr(rc));
        sqlite3_close(ret->ppDb);
        free(ret);
        return NULL;
    }
    return ret;
}

void db_close_and_free_connection(database_t *db) {
    sqlite3_close(db->ppDb);
    free(db);
}

int get_current_token(database_t *db, const char *server_id, char **output) {
    int rc, step;
    sqlite3_stmt *stmt = NULL;
    const char *token;
    static const char *sql_query = "SELECT last_token\n"\
                                   "FROM server\n"\
                                   "WHERE server_id=?;";
    rc = sqlite3_prepare_v2(db->ppDb, sql_query, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    rc = sqlite3_bind_text(stmt, 1, server_id, -1, SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_bind_text: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    step = sqlite3_step(stmt);
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
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_finalize: %s", sqlite3_errmsg(db->ppDb));
        free(*output);
        goto err_exit;
    }

    return DTC_ERR_NONE;

err_exit:
    sqlite3_finalize(stmt);
    return DTC_ERR_DATABASE;
}

int db_get_new_temp_token(database_t *db, const char *server_public_key,
                          const char **output) {
    int rc, step, affected_rows;
    char token[37];
    sqlite3_stmt *stmt = NULL;

    static const char *sql_query = "UPDATE server\n"\
                                   "SET last_token=?\n"\
                                   "WHERE public_key=?";

    rc = sqlite3_prepare_v2(db->ppDb, sql_query, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed to prepare an statment: %s",
            sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    rc = sqlite3_bind_text(stmt, 1, generate_token(&token[0]), -1,
                           SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed binding the new token public key: %s",
            sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    rc = sqlite3_bind_text(stmt, 2, server_public_key, -1, SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed binding the server public key: %s",
            sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    step = sqlite3_step(stmt);
    if(step != SQLITE_DONE) {
        LOG(LOG_LVL_ERRO, "Step error:%s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    affected_rows = sqlite3_changes(db->ppDb);
    if(affected_rows == 0) {
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_finalize(stmt);
    if( rc != SQLITE_OK) {
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

int db_is_an_authorized_key(database_t *db, const char *key) {
    int rc, step;
    sqlite3_stmt *stmt = NULL;
    static const char *sql_query = "SELECT server_id\n"\
                                   "FROM server\n"\
                                   "WHERE public_key=?;";
    rc = sqlite3_prepare_v2(db->ppDb, sql_query, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_prepare_v2: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    rc = sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_bind_text: %s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    step = sqlite3_step(stmt);
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

static int insert_server(sqlite3 *db, const char *server_key,
                         const char *server_id, const char *token) {
    char *err;
    size_t ret;
    int rc;
    char *sql_template  = "INSERT INTO server (public_key, server_id, last_token)\n"\
                          "    VALUES('%s', '%s', '%s');";
    size_t len = strlen(sql_template) +
                 strlen(server_key) +
                 strlen(server_id) +
                 strlen(token) + 1; // %s will be replaced, this isn't needed.
    char *sql_query = (char *) malloc(sizeof(char) * len);
    ret = snprintf(sql_query, len, sql_template, server_key, server_id, token);
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

static int create_tables(database_t *db) {
    unsigned int i;
    int rc;
    // TODO server_id also have to be NOT NULL
    const char *server_stmt =
                    "CREATE TABLE IF NOT EXISTS server (\n"\
                    "   public_key  TEXT PRIMARY KEY,\n"\
                    "   server_id   TEXT UNIQUE,\n"\
                    "   last_token  TEXT\n"\
                    ");";
    const char *key_share_stmt =
                    "CREATE TABLE IF NOT EXISTS key_share (\n"\
                    "   server_id   TEXT NOT NULL,\n"\
                    "   key_id      TEXT NOT NULL,\n"\
                    "   key         TEXT,\n"\
                    "   n           TEXT,\n"\
                    "   id          INTEGER,\n"\
                    "   PRIMARY KEY(server_id, key_id),\n"\
                    "   FOREIGN KEY(server_id) REFERENCES server\n"\
                    ");";
    const char *public_key_stmt =
                    "CREATE TABLE IF NOT EXISTS public_key (\n"\
                    "   server_id   TEXT NOT NULL,\n"\
                    "   key_id      TEXT NOT NULL,\n"\
                    "   n           TEXT,\n"\
                    "   m           TEXT,\n"\
                    "   e           TEXT,\n"\
                    "   PRIMARY KEY(server_id, key_id),\n"\
                    "   FOREIGN KEY(server_id, key_id) REFERENCES key_share\n"\
                    ");";
    const char *key_metainfo_stmt =
                    "CREATE TABLE IF NOT EXISTS key_metainfo (\n"\
                    "   server_id   TEXT NOT NULL,\n"\
                    "   key_id      TEXT NOT NULL,\n"\
                    "   bit_size    INTEGER,\n"\
                    "   k           INTEGER,\n"\
                    "   l           INTEGER,\n"\
                    "   vk_v        TEXT,\n"\
                    "   vk_id       INTEGER,\n"\
                    "   PRIMARY KEY(server_id, key_id),\n"\
                    "   FOREIGN KEY(server_id, key_id) REFERENCES key_share\n"\
                    ");";
    const char *verification_key_stms =
                    "CREATE TABLE IF NOT EXISTS verification_key (\n"\
                    "   id          INTEGER,\n"\
                    "   vk          TEXT,\n"\
                    "   PRIMARY KEY(id, vk)\n"\
                    ");";

    const char *tables[5][2] = {{"server", server_stmt},
                                {"key_share", key_share_stmt},
                                {"public_key", public_key_stmt},
                                {"key_metainfo", key_metainfo_stmt},
                                {"verification_key_stms", verification_key_stms}
                               };

    for(i = 0; i < 5; i++) {
        rc = create_table(db->ppDb, tables[i][0], tables[i][1]);
        if(rc)
            return rc;
    }
    return DTC_ERR_NONE;
}


START_TEST(test_create_db) {
    char *database_file = get_filepath("test_create_db");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(0, access(database_file, F_OK));

    close_and_remove_db(database_file, conn);

}
END_TEST

START_TEST(test_create_tables) {
    char *database_file = get_filepath("test_create_tables");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));

    ck_assert_int_eq(0, access(database_file, F_OK));

    close_and_remove_db(database_file, conn);

}
END_TEST

START_TEST(test_get_new_token_empty_db) {
    const char *result;
    const char *server_p_key = "a98478teqgdkg129*&&%^$%#$";
    char *database_file = get_filepath("test_get_new_token_empty_db");
    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_get_new_temp_token(conn, server_p_key, &result));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_TEST(test_get_new_token_server_not_found) {
    char *database_file = get_filepath("test_get_new_token_server_not_found");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));

    ck_assert_int_eq(-1, db_get_new_temp_token(conn, "any_key", NULL));

    close_and_remove_db(database_file, conn);

}
END_TEST

START_TEST(test_get_new_token_consistency) {

    char *database_file = get_filepath("test_get_new_token_consistency");
    char *server_key = "1(*A&S^DYHJA]&TYHJ@aklut*&@2128ha";
    char *old_token = "no_token";
    char *server_id = "server_id";
    char *current_token = NULL;
    const char *result;

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
                    db_get_new_temp_token(conn, server_key, &result));
    free((void *)result);

    // Check changed token.
    ck_assert_int_eq(DTC_ERR_NONE,
                     get_current_token(conn, server_id, &current_token));
    ck_assert_str_ne(old_token, current_token);
    ck_assert_str_ne("token", current_token);
    free(current_token);

    //Check not changed token
    ck_assert_int_eq(DTC_ERR_NONE,
                     get_current_token(conn, "rand_id", &current_token));
    ck_assert_str_eq("token", current_token);
    free(current_token);

    close_and_remove_db(database_file, conn);
}
END_TEST

START_TEST(test_db_is_an_authorized_key_empty_db) {

    char *database_file = get_filepath("test_db_is_an_authorized_key_empty_db");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ck_assert_int_eq(-1, db_is_an_authorized_key(conn, "any_key"));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_TEST(test_db_is_an_authorized_key) {

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

TCase *get_dt_tclib_database_c_test_case() {
    TCase *test_case = tcase_create("database_c");

    tcase_add_test(test_case, test_create_db);
    tcase_add_test(test_case, test_create_tables);
    //printf("%p\n%p\n", test_get_new_token_empty_db, test_get_new_token_server_not_found);

    tcase_add_test(test_case, test_get_new_token_empty_db);
    tcase_add_test(test_case, test_get_new_token_server_not_found);
    tcase_add_test(test_case, test_get_new_token_consistency);

    tcase_add_test(test_case, test_db_is_an_authorized_key_empty_db);
    tcase_add_test(test_case, test_db_is_an_authorized_key);
    return test_case;
}

#endif
