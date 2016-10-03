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
};

// For testing purpose only DO NOT USE IT.
void *get_sqlite3_conn(database_t *database_conn)
{
    return database_conn->ppDb;
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
                    "   instance_id       TEXT PRIMARY KEY,\n"\
                    "   public_key      TEXT UNIQUE,\n"\
                    "   router_token    TEXT,\n"\
                    "   pub_token       TEXT\n"\
                    ");\n";
    const char *key_stmt =
                    "CREATE TABLE IF NOT EXISTS key (\n"
                    "   key_id          TEXT NOT NULL,\n"
                    "   instance_id       TEXT NOT NULL,\n"
                    "   key_share       TEXT NOT NULL,\n"
                    "   key_metainfo    TEXT NOT NULL,\n"
                    "   PRIMARY KEY(instance_id, key_id),\n"
                    "   FOREIGN KEY(instance_id) REFERENCES instance(instance_id) "
                                                          "ON DELETE CASCADE"
                    ");\n";

    const char *new_instance_stms =
                    "CREATE TABLE IF NOT EXISTS new_instance (\n"\
                    "   instance_id   TEXT PRIMARY KEY,\n"\
                    "   public_key  TEXT UNIQUE\n"\
                    ");";

    const char *tables[3][2] = {{"instance", instance_stmt},
                                {"key", key_stmt},
                                {"new_instance", new_instance_stms},
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
database_t *db_init_connection(const char *path, int create_db_tables){
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
            sqlite3_errmsg(&ret->ppDb);
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

int db_get_instance_id(database_t *db, const char *public_key, char **output) {
    static const char *sql_query = "SELECT instance_id\n"
                                   "FROM instance\n"
                                   "WHERE public_key = ?;";
    return get_instance_id(db, sql_query, public_key, output);
}

int db_get_instance_id_from_pub_token(database_t *db, const char *pub_token,
                                    char **output) {
    static const char *sql_query = "SELECT instance_id\n"
                                   "FROM instance\n"
                                   "WHERE pub_token = ?;";
    return get_instance_id(db, sql_query, pub_token, output);
}

int db_get_instance_id_from_router_token(database_t *db, const char *router_token,
                                       char **output){
    static const char *sql_query = "SELECT instance_id\n"
                                   "FROM instance\n"
                                   "WHERE router_token = ?;";
    return get_instance_id(db, sql_query, router_token, output);
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
                                const char *sql_query, char **output) {

    int rc, step;
    sqlite3_stmt *stmt = NULL;
    const char *token;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 1, instance_id);
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

int db_get_router_token(database_t *db, const char *instance_id, char **output) {
    return db_get_current_token(
            db, instance_id, "SELECT router_token\n"
                           "FROM instance\n"
                           "WHERE instance_id= ?;\n", output);
}

int db_get_pub_token(database_t *db, const char *instance_id, char **output) {
    return db_get_current_token(
            db, instance_id, "SELECT pub_token\n"
                           "FROM instance\n"
                           "WHERE instance_id=?;\n", output);
}

int db_get_new_temp_token(database_t *db, const char *instance_public_key,
                          const char *sql_query, char **output) {
    int rc, step, affected_rows;
    char token[37];
    sqlite3_stmt *stmt = NULL;

    rc = prepare_bind_stmt(db->ppDb, sql_query, &stmt, 2,
                           get_uuid_as_char(&token[0]), instance_public_key);
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

int db_get_new_router_token(database_t *db, const char *instance_public_key,
                            char **output) {
    return db_get_new_temp_token(
            db, instance_public_key, "UPDATE instance\n"
                                   "SET router_token = ?\n"
                                   "WHERE public_key = ?;", output);
}

int db_get_new_pub_token(database_t *db, const char *instance_public_key,
                         char **output) {
    return db_get_new_temp_token(
            db, instance_public_key, "UPDATE instance\n"
                                   "SET pub_token = ?\n"
                                   "WHERE public_key = ?;", output);
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
