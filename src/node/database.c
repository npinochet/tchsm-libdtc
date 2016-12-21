#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sqlite3.h>

#include <dtc.h>

//TODO do not use this anymore.
#include "blocking_sql3.h"
#include "database.h"
#include "logger.h"
#include "utilities.h"

struct database_conn {
   sqlite3 *ppDb;

   multiple_connections_t mult_conn_behaviour;
};

// For testing purpose only DO NOT USE IT.
void *get_sqlite3_conn(database_t *database_conn)
{
    return database_conn->ppDb;
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

int sqlite3_my_blocking_exec_stmt(sqlite3 *db, sqlite3_stmt *stmt) {
    int rc, step;
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

int create_tables(database_t *db) {
    unsigned int i;
    int rc;
    // TODO public_key also have to be NOT NULL
    const char *instance_stmt =
                "CREATE TABLE IF NOT EXISTS instance (\n"\
                "   instance_id         TEXT PRIMARY KEY,\n"\
                "   public_key          TEXT UNIQUE,\n"\
                "   ip                  TEXT\n"\
                ");\n";

    const char *key_stmt =
                "CREATE TABLE IF NOT EXISTS key (\n"
                "   key_id          TEXT NOT NULL,\n"
                "   instance_id       TEXT NOT NULL,\n"
                "   key_share       TEXT NOT NULL,\n"
                "   key_metainfo    TEXT NOT NULL,\n"
                "   PRIMARY KEY(instance_id, key_id),\n"
                "   FOREIGN KEY(instance_id) REFERENCES instance(instance_id) "
                "                                            ON DELETE CASCADE"
                ");\n";

    const char *instance_connection_stmt =
                "CREATE TABLE IF NOT EXISTS instance_connection(\n"\
                "   instance_id TEXT NOT NULL,\n"\
                "   rowid INTEGER PRIMARY KEY,\n"\
                "   connection_identifier TEXT UNIQUE,\n"\
                "   router_token TEXT UNIQUE,\n"\
                "   pub_token TEXT UNIQUE,\n"\
                "   FOREIGN KEY(instance_id) REFERENCES instance(instance_id) "\
                "                                       ON DELETE CASCADE\n"\
                "   UNIQUE(instance_id, connection_identifier)\n"
                ");";

    const char *new_instance_stms =
                "CREATE TABLE IF NOT EXISTS new_instance (\n"\
                "   instance_id   TEXT PRIMARY KEY,\n"\
                "   public_key  TEXT UNIQUE\n"\
                ");";

    const char *tables[4][2] = {
            {"instance", instance_stmt},
            {"key", key_stmt},
            {"instance_connection", instance_connection_stmt},
            {"new_instance", new_instance_stms},
    };

    for(i = 0; i < 4; i++) {
        rc = create_table(db->ppDb, tables[i][0], tables[i][1]);
        if(rc)
            return rc;
    }
    return DTC_ERR_NONE;
}


// API
database_t *db_init_connection(const char *path, int create_db_tables,
                               multiple_connections_t mult_conn_behaviour)
{
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
#if (SQLITE_VERSION_NUMBER >= 3007015)
            sqlite3_errstr(rc));
#else
            sqlite3_errmsg(ret->ppDb));
#endif
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
    if(create_db_tables){
        rc = create_tables(ret);
    }
    if(rc != DTC_ERR_NONE) {
        db_close_and_free_connection(ret);
        return NULL;
    }
    sqlite3_busy_timeout(ret->ppDb, 500);
    ret->mult_conn_behaviour = mult_conn_behaviour;
    return ret;
}

void db_close_and_free_connection(database_t *db) {
    sqlite3_close(db->ppDb);
    free(db);
}

int db_add_new_instance(database_t *db, const char *id, const char *public_key) {
    int rc, affected_rows, step;
    sqlite3_stmt *stmt = NULL;
    char *add_template  =
            "INSERT OR ABORT INTO new_instance (instance_id, public_key)\n"\
            "    VALUES(?, ?);";

    rc = prepare_bind_stmt(db->ppDb, add_template, &stmt, 2, id, public_key);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    sqlite3_finalize(stmt);
    if(step == SQLITE_DONE) {
        affected_rows = sqlite3_changes(db->ppDb);
        if(affected_rows != 1) {
            LOG(LOG_LVL_CRIT, "Add instance affected %d rows instead of 1",
                affected_rows);
            return DTC_ERR_DATABASE;
        }
        return DTC_ERR_NONE;
    }
    else {
        LOG(LOG_LVL_ERRO, "Add new instance failed: %s",
            sqlite3_errmsg(db->ppDb));
        return DTC_ERR_DATABASE;
    }
}

int db_update_instances(database_t *db) {
    int rc;
    static const char *delete =
        "DELETE\n"
        "FROM instance\n"
        "WHERE instance_id NOT IN\n"
        "   (SELECT instance_id\n"
        "    FROM new_instance\n"
        "    WHERE instance.instance_id = new_instance.instance_id);\n";

    static const char *update_existing =
        "UPDATE instance\n"
        "SET public_key = (SELECT public_key\n"
        "                  FROM new_instance\n"
        "                  WHERE instance_id = instance.instance_id)\n"
        "WHERE instance_id IN\n"
        "   (SELECT instance_id\n"
        "    FROM new_instance\n"
        "    WHERE (instance_id = new_instance.instance_id and\n"
        "        public_key != instance.public_key))\n";

    static const char *create_new =
        "INSERT INTO instance(instance_id, public_key)\n"
        "SELECT instance_id, public_key\n"
        "FROM new_instance\n"
        "WHERE instance_id NOT IN (SELECT instance_id FROM instance);\n";

    static const char *delete_table =
        "DELETE FROM new_instance";

    rc = create_tables(db);
    if(rc != DTC_ERR_NONE)
        return rc;

    // First, delete all instances not in new_instances.
    rc = sqlite3_my_blocking_exec(db->ppDb, delete);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error deleting instance.");
        return rc;
    }
    LOG(LOG_LVL_INFO, "%d deleted instances on update.",
        sqlite3_changes(db->ppDb));

    // Then update existing.
    rc = sqlite3_my_blocking_exec(db->ppDb, update_existing);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error updating instance.");
        return rc;
    }

    LOG(LOG_LVL_INFO, "%d instances were updated with a different public_key.",
        sqlite3_changes(db->ppDb));

    // And move the new instances from new_instance to instance.
    rc = sqlite3_my_blocking_exec(db->ppDb, create_new);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error inserting new instances.");
        return rc;
    }
    LOG(LOG_LVL_INFO, "%d new instances were added.", sqlite3_changes(db->ppDb));


    rc = sqlite3_my_blocking_exec(db->ppDb, delete_table);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT, "Error deleting new_instance table.");
        return rc;
    }


    return DTC_ERR_NONE;
}

static int get_connection_id_from_token(database_t *db, const char *sql_query,
                                        const char *token, char **output)
{
    int rc, step, buf_len;
    sqlite3_stmt *stmt = NULL;
    const char *instance_id, *conn_id;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, token);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        instance_id = (const char *)sqlite3_column_text(stmt, 0);
        conn_id = (const char *)sqlite3_column_text(stmt, 1);
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

    // 2 = 1 NULL BYTE + separator (-)
    buf_len = strlen(instance_id) + strlen(conn_id) + 2;
    *output = (char *) malloc(sizeof(char) * buf_len);

    rc = snprintf(*output, buf_len, "%s-%s", instance_id, conn_id);
    if(rc >= buf_len || rc < 0) {
        LOG(LOG_LVL_ERRO, "snprintf failed: %d", rc);
        free(output);
        sqlite3_finalize(stmt);
        return DTC_ERR_INTERN;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK)
        LOG(LOG_LVL_ERRO, "sqlite3_finalize %s", sqlite3_errmsg(db->ppDb));
    return DTC_ERR_NONE;
}

static int get_instance_id(database_t *db, const char *sql_query,
                           const char* key, char **output) {
    int rc, step;
    const char *instance_id;
    sqlite3_stmt *stmt = NULL;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, key);
    if(rc != DTC_ERR_NONE)
        return rc;

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        instance_id = (const char *)sqlite3_column_text(stmt, 0);
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

    *output = strdup((const char *)instance_id);

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK)
        LOG(LOG_LVL_ERRO, "sqlite3_finalize %s", sqlite3_errmsg(db->ppDb));

    return DTC_ERR_NONE;

}

static int get_current_ip(database_t *db, const char *instance_id,
                          char **output)
{
    int rc, step;
    sqlite3_stmt *stmt = NULL;

    const char *sql_query = "SELECT ip\n"\
                            "FROM instance\n"\
                            "WHERE instance_id = ?;";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, instance_id);
    if(rc != DTC_ERR_NONE)
        return rc;
    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        *output = (char *)sqlite3_column_text(stmt, 0);
        if(*output != NULL)
            *output = strdup(*output);
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

static int update_ip(database_t *db, const char *instance_id, const char *ip)
{
    int rc;
    sqlite3_stmt *stmt = NULL;
    const char *sql_query = "UPDATE instance\n"\
                            "SET ip = ?\n"\
                            "WHERE instance_id = ?";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, ip, instance_id);
    if(rc != DTC_ERR_NONE)
        return rc;

    return sqlite3_my_blocking_exec_stmt(db->ppDb, stmt);
}

int db_get_key(database_t *db, const char *instance_id, const char *key_id,
               char **key_share, char **key_metainfo)
{
    int rc, step;
    sqlite3_stmt *stmt = NULL;

    const char *sql_query = "SELECT key_share, key_metainfo\n"
                            "FROM key\n"
                            "WHERE key_id = ? and instance_id = ?;";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, key_id, instance_id);
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

int get_instance_id_from_token(database_t *db, const char *token_name,
                               const char *token, char **output)
{
    static const char *sql_query_template = "SELECT instance_id\n"\
                                            "FROM instance_connection\n"\
                                            "WHERE %s = ?;";
    size_t buf_len = strlen(sql_query_template) + strlen(token_name) + 1;
    int ret_val;
    char *sql_query = malloc(sizeof(char) * buf_len);
    ret_val = snprintf(sql_query, buf_len, sql_query_template, token_name);
    if(ret_val >= buf_len) {
        LOG(LOG_LVL_ERRO, "Buffer (%zu) too small, needed (%d)", buf_len,
            ret_val);
        free(sql_query);
        return DTC_ERR_INTERN;
    }

    ret_val = get_instance_id(db, sql_query, token, output);
    free(sql_query);
    return ret_val;
}

/**
 * Retrieve the instance_id of the instance with public_key.
 *
 * @param db Active database connection.
 * @param public_key Public key of the instance.
 * @param ouput On a success call, the instance_id will be pointed by *output.
 *      The memory is dynamic and the caller take responsibility of freeing it
 *      on success.
 *
 *  @return DTC_ERR_NONE on success, a proper positive error code if something
 *      fails or -1 if the instance is not stored in the database.
 */

int db_get_instance_id(database_t *db, const char *public_key, char **output) {
    static const char *sql_query = "SELECT instance_id\n"
                                   "FROM instance\n"
                                   "WHERE public_key = ?;";
    return get_instance_id(db, sql_query, public_key, output);
}

int db_get_instance_id_from_pub_token(database_t *db, const char *pub_token,
                                    char **output) {
    return get_instance_id_from_token(db, "pub_token", pub_token, output);
}

int db_get_instance_id_from_router_token(database_t *db, const char *router_token,
                                       char **output){
    return get_instance_id_from_token(db, "router_token", router_token, output);
}

int db_get_connection_id_from_router_token(database_t *db, const char *router_token,
                                           char **output)
{
    static const char* sql_query = "SELECT instance_id, connection_identifier\n"
                                   "FROM instance JOIN instance_connection\n"
                                   "USING (instance_id)\n"
                                   "WHERE router_token = ?;";
    return get_connection_id_from_token(db, sql_query, router_token, output);
}

int db_get_connection_id_from_pub_token(database_t *db, const char *pub_token,
                                        char **output)
{
    static const char* sql_query = "SELECT instance_id, connection_identifier\n"
                                   "FROM instance JOIN instance_connection\n"
                                   "USING (instance_id)\n"
                                   "WHERE pub_token = ?;";
    return get_connection_id_from_token(db, sql_query, pub_token, output);
}

static int clean_empty_instance_conn(database_t *db)
{
    const char *sql_clean = "DELETE\n"\
                            "FROM instance_connection\n"\
                            "WHERE router_token is NULL AND pub_token is NULL;";

    return sqlite3_my_blocking_exec(db->ppDb, sql_clean);
}

static int set_conection_id_to_token(database_t *db, const char *token_name,
                                     const char *token, const char *conn_id)
{
    int ret_val, step, rc;
    char *sql_update_template = "UPDATE instance_connection\n"\
                                "SET connection_identifier = ?\n"\
                                "WHERE %s = ?;";
    char *sql_remove_token_template = "UPDATE instance_connection\n"\
                                      "SET %s = NULL\n"\
                                      "WHERE %s = ?;";
    char *sql_token_update_template =
            "UPDATE instance_connection\n"\
            "SET %s = ?\n"
            "WHERE connection_identifier = ? AND instance_id = ?";
    size_t buf_len = strlen(sql_update_template) + strlen(token_name) + 1;
    char *sql_update = (char *) malloc(sizeof(char) * buf_len);
    char *sql_remove_token, *sql_token_update, *instance_id;
    ret_val = snprintf(sql_update, buf_len, sql_update_template, token_name);
    sqlite3_stmt *stmt = NULL, *stmt2 = NULL;
    if(ret_val >= buf_len) {
        LOG(LOG_LVL_ERRO, "Buffer (%zu) not big enough, needed %d", buf_len,
            ret_val);
        return DTC_ERR_DATABASE;
    }

    ret_val = prepare_bind_stmt(db->ppDb, sql_update, &stmt, 2, conn_id, token);
    if(ret_val != DTC_ERR_NONE) {
        free(sql_update);
        return ret_val;
    }

    step = sqlite3_blocking_step(stmt);
    sqlite3_finalize(stmt);
    free(sql_update);
    if(step == SQLITE_DONE)
        return DTC_ERR_NONE;

    // If the previous failed, the connection identifier already existed,
    // do the update in that row.
    buf_len = strlen(sql_remove_token_template) + 2 * strlen(token_name) + 1;
    sql_remove_token = (char *) malloc(sizeof(char) * buf_len);
    ret_val = snprintf(sql_remove_token, buf_len, sql_remove_token_template,
                       token_name, token_name);
    if(ret_val >= buf_len) {
        LOG(LOG_LVL_ERRO, "Buffer (%zu) not big enough, needed %d", buf_len,
            ret_val);
        free(sql_remove_token);
        return DTC_ERR_DATABASE;
    }

    buf_len = strlen(sql_token_update_template) + strlen(token_name) + 1;
    sql_token_update = (char *) malloc(sizeof(char) * buf_len);
    ret_val = snprintf(sql_token_update, buf_len, sql_token_update_template,
                       token_name);
    if(ret_val >= buf_len) {
        LOG(LOG_LVL_ERRO, "Buff (%zu) too small, needed %d", buf_len, ret_val);
        free(sql_token_update);
        free(sql_remove_token);
        return DTC_ERR_DATABASE;
    }

    ret_val = get_instance_id_from_token(db, token_name, token, &instance_id);
    if(ret_val != DTC_ERR_NONE) {
        free(sql_token_update);
        free(sql_remove_token);
        return ret_val;
    }

    stmt = NULL;
    ret_val = prepare_bind_stmt(db->ppDb, sql_remove_token, &stmt, 1, token);
    if(ret_val != DTC_ERR_NONE) {
        free(sql_token_update);
        free(sql_remove_token);
        free(instance_id);
        return ret_val;
    }

    ret_val = prepare_bind_stmt(db->ppDb, sql_token_update, &stmt2, 3, token,
                                conn_id, instance_id);
    if(ret_val != DTC_ERR_NONE) {
        sqlite3_finalize(stmt);
        free(instance_id);
        free(sql_token_update);
        free(sql_remove_token);
        return ret_val;
    }

    rc = sqlite3_exec(db->ppDb, "BEGIN", 0, 0, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Error starting a transaction");
        sqlite3_finalize(stmt);
        sqlite3_finalize(stmt2);
        free(instance_id);
        free(sql_token_update);
        free(sql_remove_token);
        return DTC_ERR_DATABASE;
    }

    rc = sqlite3_my_blocking_exec_stmt(db->ppDb, stmt);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_ERRO, "Error removing token, doing a rollback...");
        sqlite3_exec(db->ppDb, "ROLLBACK", 0, 0, 0);
        sqlite3_finalize(stmt2);
        free(instance_id);
        free(sql_token_update);
        free(sql_remove_token);
        return rc;
    }
    free(sql_remove_token);

    rc = sqlite3_my_blocking_exec_stmt(db->ppDb, stmt2);
    free(instance_id);
    free(sql_token_update);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_ERRO, "Error updating token, doing a rollback...");
        sqlite3_exec(db->ppDb, "ROLLBACK", 0, 0, 0);
        return rc;
    }

    rc = sqlite3_exec(db->ppDb, "COMMIT", 0, 0, 0);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Error set_connection_id_to_token transaction");
        sqlite3_exec(db->ppDb, "ROLLBACK", 0, 0, 0);
        return DTC_ERR_DATABASE;
    }

    if(DTC_ERR_NONE != clean_empty_instance_conn(db))
        LOG(LOG_LVL_ERRO, "Unable to clean empty instances.");

    return DTC_ERR_NONE;
}

static int get_identity_and_instance_from_token(
        database_t *db, const char *token_name, const char *token,
        const char *connection_id, char **identity, char **instance_id)
{
    static const char* sql_template =
                            "SELECT instance_id, connection_identifier\n"
                            "FROM instance_connection\n"
                            "WHERE %s = ?;";
    char *sql_query, *db_conn_id;
    sqlite3_stmt *stmt;
    int ret_val, step, rc;
    size_t buf_len = strlen(sql_template) + strlen(token_name) + 1;

    sql_query = (char *) malloc(sizeof(char) * buf_len);
    ret_val = snprintf(sql_query, buf_len, sql_template, token_name);
    if(ret_val >= buf_len) {
        LOG(LOG_LVL_ERRO, "Buffer (%zu) not big enough, needed %d", buf_len,
            ret_val);
        return DTC_ERR_DATABASE;
    }

    ret_val = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, token);
    if(ret_val != DTC_ERR_NONE) {
        free(sql_query);
        return ret_val;
    }

    step = sqlite3_blocking_step(stmt);
    if(step == SQLITE_ROW) {
        *instance_id = (char *)sqlite3_column_text(stmt, 0);
        db_conn_id = (char *)sqlite3_column_text(stmt, 1);
    }
    else if(step == SQLITE_DONE) {
        free(sql_query);
        sqlite3_finalize(stmt);
        return -1;
    }
    else{
        LOG(LOG_LVL_ERRO, "sqlite3_step: %s", sqlite3_errmsg(db->ppDb));
        free(sql_query);
        sqlite3_finalize(stmt);
        return DTC_ERR_DATABASE;
    }

    ret_val = DTC_ERR_NONE;

    if(db_conn_id == NULL && connection_id == NULL) {
        LOG(LOG_LVL_ERRO, "Connection id not available.");
        ret_val = DTC_ERR_INTERN;
    }
    else if(connection_id == NULL) {
        *instance_id = strdup(*instance_id);
        *identity = create_identity(*instance_id, db_conn_id);
        if(instance_id == NULL || *identity == NULL) {
            LOG(LOG_LVL_ERRO, "Out of memory");
            ret_val =  DTC_ERR_NOMEM;
        }
    }
    else if(db_conn_id == NULL || strcmp(db_conn_id, connection_id) != 0) {
        if(db_conn_id != NULL)
            LOG(LOG_LVL_WARN, "Connection id changed. %s -> %s", db_conn_id,
                connection_id);
        ret_val =  set_conection_id_to_token(db, token_name, token,
                                             connection_id);
        if(ret_val != DTC_ERR_NONE)
            LOG(LOG_LVL_ERRO, "Couldn't set the connection id to the token");
        *identity = create_identity(*instance_id, connection_id);
        *instance_id = strdup(*instance_id);
        if(*identity == NULL || instance_id == NULL)
            ret_val = DTC_ERR_NOMEM;
    }
    else {
        *instance_id = strdup(*instance_id);
        *identity = create_identity(*instance_id, connection_id);
        if(*identity == NULL || instance_id == NULL)
            ret_val = DTC_ERR_NOMEM;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "sqlite3_finalize: %s", sqlite3_errmsg(db->ppDb));
        return DTC_ERR_DATABASE;
    }
    free(sql_query);
    return ret_val;
}

int db_get_identity_and_instance_from_router_token(
        database_t *db, const char *router_token, const char *connection_id,
        char **identity, char **instance_id)
{
    return get_identity_and_instance_from_token(db, "router_token",
                                                router_token, connection_id,
                                                identity, instance_id);
}

int db_get_identity_and_instance_from_pub_token(
        database_t *db, const char *pub_token, const char *connection_id,
        char **identity, char **instance_id)
{
    return get_identity_and_instance_from_token(db, "pub_token", pub_token,
                                                connection_id, identity,
                                                instance_id);
}

int db_is_key_id_available(database_t *db, const char *instance_id,
                           const char *key_id) {
    sqlite3_stmt *stmt;
    int rc, step;
    char *sql_query = "SELECT instance_id\n"
                      "FROM key\n"
                      "WHERE instance_id = ? and key_id = ?;\n";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, instance_id, key_id);
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

static int db_get_current_token(database_t *db, const char *instance_id,
                                const char *connection_identifier,
                                const char *sql_query, char **output) {

    int rc, step;
    sqlite3_stmt *stmt = NULL;
    const char *token;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, instance_id,
                           connection_identifier);
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

int db_get_router_token(database_t *db, const char *instance_id,
                        const char *conn_identifier, char **output) {
    return db_get_current_token(
            db, instance_id, conn_identifier,
            "SELECT router_token\n"
            "FROM instance_connection\n"
            "WHERE instance_id= ? AND connnection_identifier = ?;\n", output);
}

int db_get_pub_token(database_t *db, const char *instance_id,
                     const char *conn_identifier, char **output) {
    return db_get_current_token(
            db, instance_id, conn_identifier,
            "SELECT pub_token\n"
            "FROM instance_connection\n"
            "WHERE instance_id=? AND connection_identifier = ?;\n", output);
}

int db_get_new_temp_token(database_t *db, const char *instance_public_key,
                          const char *token_name, const char *ip, char **output) {
    char *sql_delete, *sql_query, *instance_id, *stored_ip;
    int rc, ret_val, step, affected_rows;
    size_t bufer_len;
    const char *sql_delete_template;
    char token[37];
    sqlite3_stmt *stmt = NULL;

    const char *sql_template =
                    "INSERT INTO instance_connection\n"\
                    "(instance_id, %s)\n"\
                    "VALUES(?, ?)";

    rc = db_get_instance_id(db, instance_public_key, &instance_id);
    if(rc != DTC_ERR_NONE)
        return rc;

    if(db->mult_conn_behaviour == ONE_CONNECTION) {
        // It's nice to have it up to date but it isn't important for this
        // multiple connection behaviour.
        update_ip(db, instance_id, ip);
        // Drop all other connections
        sql_delete_template = "UPDATE instance_connection\n"\
                              "SET %s = NULL\n"
                              "WHERE instance_id = ?";

        bufer_len = strlen(sql_delete_template) + strlen(token_name) + 1;
        sql_delete = (char *) malloc(sizeof(char) * bufer_len);
        ret_val = snprintf(sql_delete, bufer_len, sql_delete_template,
                           token_name);
        if(ret_val >= bufer_len) {
            LOG(LOG_LVL_CRIT, "Buf (%zu) too small (%d)", bufer_len, ret_val);
            free(instance_id);
            free(sql_delete);
            return DTC_ERR_INTERN;
        }

        rc = prepare_bind_stmt(db->ppDb, sql_delete, &stmt, 1, instance_id);
        if(rc != DTC_ERR_NONE) {
            free(instance_id);
            free(sql_delete);
            return rc;
        }

        rc = sqlite3_my_blocking_exec_stmt(db->ppDb, stmt);
        free(sql_delete);
        if(rc != DTC_ERR_NONE) {
            free(instance_id);
            return rc;
        }
    }

    else if(db->mult_conn_behaviour == SAME_IP) {
        rc = get_current_ip(db, instance_id, &stored_ip);
        if(rc != DTC_ERR_NONE) {
            free(instance_id);
            return rc;
        }

        // If different IP
        if(stored_ip == NULL || strcmp(stored_ip, ip) != 0) {
            // If different ip, remove previous tokens
            if(stored_ip != NULL) {
                LOG(LOG_LVL_INFO, "Connection from different IP: %s", ip);

                sql_delete = "DELETE\n"
                            "FROM instance_connection\n"
                            "WHERE instance_id = ?;";

                rc = prepare_bind_stmt(db->ppDb, sql_delete, &stmt, 1,
                                    instance_id);
                if(rc != DTC_ERR_NONE) {
                    free(stored_ip);
                    free(instance_id);
                    return rc;
                }

                rc = sqlite3_my_blocking_exec_stmt(db->ppDb, stmt);
                if(rc != DTC_ERR_NONE) {
                    free(stored_ip);
                    free(instance_id);
                    return rc;
                }
            }

            rc = update_ip(db, instance_id, ip);
            if(rc != DTC_ERR_NONE) {
                free(stored_ip);
                free(instance_id);
                return rc;
            }
        }
        free(stored_ip);
    }
    else {
        free(instance_id);
        LOG(LOG_LVL_CRIT, "Behaviour not supported");
        return DTC_ERR_INVALID_VAL;
    }

    bufer_len = strlen(sql_template) + strlen(token_name) + 1;
    sql_query = (char *) malloc(sizeof(char) * bufer_len);
    rc = snprintf(sql_query, bufer_len, sql_template, token_name);
    if(rc >= bufer_len) {
        free(instance_id);
        LOG(LOG_LVL_CRIT, "Error writing sql query into buffer.");
        return DTC_ERR_INTERN;
    }

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2,
                           instance_id, get_uuid_as_char(&token[0]));
    if(rc != DTC_ERR_NONE) {
        free(sql_query);
        free(instance_id);
        return rc;
    }

    step = sqlite3_blocking_step(stmt);
    if(step != SQLITE_DONE) {
        free(sql_query);
        free(instance_id);
        LOG(LOG_LVL_ERRO, "Step error:%s", sqlite3_errmsg(db->ppDb));
        goto err_exit;
    }

    affected_rows = sqlite3_changes(db->ppDb);
    if(affected_rows == 0) {
        sqlite3_finalize(stmt);
        free(sql_query);
        free(instance_id);
        LOG(LOG_LVL_WARN, "Trying to get new token for not authorized master");
        return -1;
    }

    rc = sqlite3_finalize(stmt);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Failed finalizing the statment: %s",
            sqlite3_errmsg(db->ppDb));
        free(sql_query);
        free(instance_id);
        return DTC_ERR_DATABASE;
    }

    free(sql_query);
    free(instance_id);
    *output = strdup(&token[0]);

    if(DTC_ERR_NONE != clean_empty_instance_conn(db))
        LOG(LOG_LVL_WARN, "Couldn't clean empty rows");
    return DTC_ERR_NONE;

err_exit:
    sqlite3_finalize(stmt);
    return DTC_ERR_DATABASE;
}

int db_get_new_router_token(database_t *db, const char *instance_public_key,
                            const char *ip, char **output) {
    return db_get_new_temp_token(db, instance_public_key,
                                 "router_token", ip, output);
}

int db_get_new_pub_token(database_t *db, const char *instance_public_key,
                         const char *ip, char **output) {
    return db_get_new_temp_token(db, instance_public_key,
                                 "pub_token", ip, output);
}

int db_store_key(database_t *db, const char *instance_id, const char *key_id,
                 const char *metainfo, const char *key_share) {

    int rc, step, affected_rows;
    sqlite3_stmt *stmt;
    char *sql_query  = "INSERT INTO key "
                       "(instance_id, key_id, key_metainfo, key_share)\n"
                       "VALUES (?, ?, ?, ?);";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 4, instance_id, key_id,
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
        LOG(LOG_LVL_ERRO, "Key %s from instance %s couldn't be inserted.", key_id,
            instance_id);
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
    static const char *sql_query = "SELECT instance_id\n"
                                   "FROM instance\n"
                                   "WHERE public_key=?;";
    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, key);
    if(rc != DTC_ERR_NONE)
        return rc;

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

int db_delete_key(database_t *db, const char *instance_id, const char *key_id){
    int rc, step, affected_rows;
    sqlite3_stmt *stmt = NULL;
    static const char *sql_query = "DELETE\n"
                                   "FROM key\n"
                                   "WHERE instance_id = ? and key_id = ?;";

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2, instance_id, key_id);
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
            instance_id, key_id);
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
