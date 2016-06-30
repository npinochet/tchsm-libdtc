#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <check.h>

#include <dtc.h>

#include "logger.h"

#include "../src/node/database.h"

#define START_MY_TEST(test_name) START_TEST(test_name)\
                                 LOG(LOG_LVL_INFO, "Testing: %s.", #test_name);

#define DT_TCLIB_TEST_DIRECTORY "/tmp/dt_tclib_test/"
#define FILENAME_BUFF_SIZE 200
// TODO IF a test fails the file might remain in the temp folder, we need to
// change this kind of check or figure out some way to do a clean up.

static sqlite3 *get_sqlite3_connection(database_t *database_conn)
{
    return (sqlite3 *) get_sqlite3_conn(database_conn);
}
static char *get_filepath(const char *file) {

    const char *testing_dir = DT_TCLIB_TEST_DIRECTORY;
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
static int insert_instance(sqlite3 *db, const char *instance_key,
                         const char *instance_id, const char *token) {
    char *err;
    size_t ret;
    int rc;
    char *sql_template  = "INSERT INTO instance (public_key, instance_id, "
                                              "router_token, pub_token)\n"
                          "    VALUES('%s', '%s', '%s', '%s');";
    size_t len = strlen(sql_template) +
                 strlen(instance_key) +
                 strlen(instance_id) +
                 strlen(token) +
                 strlen(token) + 1; // %s will be replaced, this isn't needed.
    char *sql_query = (char *) malloc(sizeof(char) * len);
    ret = snprintf(sql_query, len, sql_template, instance_key, instance_id, token,
                   token);
    ck_assert(ret < len);

    rc = sqlite3_exec(db, sql_query, NULL, NULL, &err);
    if(rc != SQLITE_OK) {
        LOG(LOG_LVL_ERRO, "Error inserting instance: %s\n%s", err, sql_query);
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
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    rc = sqlite3_exec(ppDb, "PRAGMA foreign_keys;", foreign_key_callback, NULL,
                      NULL);
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
    const char *instance_p_key = "a98478teqgdkg129*&&%^$%#$";
    char *database_file = get_filepath("test_get_new_token_empty_db");
    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ck_assert_int_eq(-1,
                     db_get_new_router_token(conn, instance_p_key, &result));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_get_new_token_instance_not_found) {
    char *database_file = get_filepath("test_get_new_token_instance_not_found");

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
    char *instance_key = "1(*A&S^DYHJA]&TYHJ@aklut*&@2128ha";
    char *old_token = "no_token";
    char *instance_id = "instance_id";
    char *current_token = NULL;
    char *result;
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));
    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));

    ck_assert_int_eq(DTC_ERR_NONE,
                     insert_instance(ppDb, instance_key, instance_id, old_token));
    ck_assert_int_eq(DTC_ERR_NONE,
                     insert_instance(ppDb, "other_key", "rand_id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                    db_get_new_router_token(conn, instance_key, &result));
    free((void *)result);

    // Check changed token.
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_get_router_token(conn, instance_id, &current_token));
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
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));
    ck_assert_int_eq(DTC_ERR_NONE,
                     insert_instance(ppDb, "valid_key", "id", "token"));

    ck_assert_int_eq(1, db_is_an_authorized_key(conn, "valid_key"));
    ck_assert_int_eq(0, db_is_an_authorized_key(conn, "not_valid_key"));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_db_add_new_instance) {
    char *database_file = get_filepath("test_db_add_new_instance");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, create_tables(conn));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id_1", "key_1"));
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_add_new_instance(conn, "id_1", "key_3"));
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_add_new_instance(conn, "id_n", "key_1"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id_n", "key_n"));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_instances_empty_db) {
    char *database_file = get_filepath("test_update_instance_empty_tables");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE, db_update_instances(conn));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_instances_no_old_instances) {
    char *aux;
    char *database_file = get_filepath("test_update_instances_no_old_instances");

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id", "key"));
    ck_assert_int_eq(DTC_ERR_DATABASE,
                     db_add_new_instance(conn, "id", "key_2"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id_2", "key_2"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_instances(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "key", &aux));
    ck_assert_str_eq("id", aux);
    free(aux);

    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "key_2", &aux));
    ck_assert_str_eq("id_2", aux);
    free(aux);
    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_instances_update_only) {
    char *aux;
    char *database_file = get_filepath("test_update_instances_update_only");
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id", "key2"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_instances(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "key2", &aux));
    ck_assert_str_eq("id", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_instances_replace) {
    char *aux;
    char *database_file = get_filepath("test_update_instances_replace");
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id2", "key"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_instances(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "key", &aux));
    ck_assert_str_eq("id2", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_instances_nothing_to_update) {
    char *aux;
    char *database_file = get_filepath("test_update_instances_nothing_to_update");
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "id", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id", "key"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_instances(conn));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "key", &aux));
    ck_assert_str_eq("id", aux);
    free(aux);

    close_and_remove_db(database_file, conn);
}
END_TEST
START_MY_TEST(test_update_instances_delete_only) {
    char *aux;
    char *database_file = get_filepath("test_update_instances_delete_only");
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "id", "token"));
    ck_assert_int_eq(0, insert_instance(ppDb, "key2", "id2", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_instances(conn));


    ck_assert_int_eq(-1, db_get_instance_id(conn, "key", &aux));
    ck_assert_int_eq(-1, db_get_instance_id(conn, "key2", &aux));

    close_and_remove_db(database_file, conn);
}
END_TEST

START_MY_TEST(test_update_instances_mix_operations) {
    char *aux;
    char *database_file = get_filepath("test_update_instances_just_update");
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "id", "token"));
    ck_assert_int_eq(0, insert_instance(ppDb, "key2", "id2", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id2", "updatedkey2"));
    ck_assert_int_eq(DTC_ERR_NONE,
                     db_add_new_instance(conn, "id3", "key3"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_update_instances(conn));


    ck_assert_int_eq(-1, db_get_instance_id(conn, "key", &aux));
    ck_assert_int_eq(-1, db_get_instance_id(conn, "key2", &aux));


    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "updatedkey2", &aux));
    ck_assert_str_eq("id2", aux);
    free(aux);

    ck_assert_int_eq(DTC_ERR_NONE, db_get_instance_id(conn, "key3", &aux));
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
    sqlite3 *ppDb;

    keys[0] = "key_metainfo_";
    keys[1] = "k_share_";

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "s_id", "token"));
    //ck_assert_int_eq(0, insert_instance(conn->ppDb, "key2", "s_id2", "token"));

    ck_assert_int_eq(DTC_ERR_NONE,
                     db_store_key(conn, "s_id", "k_id", keys[0], keys[1]));
    rc = sqlite3_exec(ppDb, "SELECT key_metainfo, key_share\n"
                            "FROM key\n"
                            "WHERE instance_id = 's_id' and "
                                  "key_id = 'k_id';\n",
                      get_keys_callback, &keys, NULL);

    ck_assert_int_eq(SQLITE_OK, rc);
    // This check that the callback was called.
    ck_assert_ptr_eq(NULL, *keys);

    keys[0] = "key_metainfo_";
    keys[1] = "k_share_";
    ck_assert_int_eq(0, insert_instance(ppDb, "key2", "s2_id", "token"));
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
    sqlite3 *ppDb;

    keys[0][0] = "key_metainfo_";
    keys[0][1] = "key_share";

    keys[1][0] = "metainfo_";
    keys[1][1] = "share";

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key" ,"s_id", "token"));

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
    sqlite3 *ppDb;

    ck_assert_int_eq(-1, access(database_file, F_OK));

    database_t *conn = db_init_connection(database_file);
    ck_assert(conn != NULL);
    ppDb = get_sqlite3_connection(conn);

    ck_assert_int_eq(0, insert_instance(ppDb, "key", "s_id", "token"));

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

void add_test_cases(Suite *s) {

    TCase *test_case = tcase_create("database_c");
    tcase_add_test(test_case, test_foreign_keys_support);

    tcase_add_test(test_case, test_create_db);
    tcase_add_test(test_case, test_create_tables);
    //printf("%p\n%p\n", test_get_new_token_empty_db, test_get_new_token_instance_not_found);

    tcase_add_test(test_case, test_get_new_token_empty_db);
    tcase_add_test(test_case, test_get_new_token_instance_not_found);
    tcase_add_test(test_case, test_get_new_token_consistency);

    tcase_add_test(test_case, test_db_is_an_authorized_key_empty_db);
    tcase_add_test(test_case, test_db_is_an_authorized_key);

    tcase_add_test(test_case, test_db_add_new_instance);

    tcase_add_test(test_case, test_update_instances_empty_db);
    tcase_add_test(test_case, test_update_instances_no_old_instances);
    tcase_add_test(test_case, test_update_instances_update_only);
    tcase_add_test(test_case, test_update_instances_nothing_to_update);
    tcase_add_test(test_case, test_update_instances_replace);
    tcase_add_test(test_case, test_update_instances_delete_only);
    tcase_add_test(test_case, test_update_instances_mix_operations);

    tcase_add_test(test_case, test_store_key_simple);

    tcase_add_test(test_case, test_get_key);

    tcase_add_test(test_case, test_delete_key_simple);

    suite_add_tcase(s, test_case);
}

static void clean_directory(const char *directory)
{

    DIR *d;
    struct dirent *p;
    int res;
    char buff[FILENAME_BUFF_SIZE];
    d = opendir(directory);
    while((p = readdir(d))) {
        if(!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
            continue;
        snprintf(buff, FILENAME_BUFF_SIZE, "%s%s", DT_TCLIB_TEST_DIRECTORY,
                 p->d_name);
        res = remove(buff);
        assert(0 == res); //This isn't called in a test routine, ck_assert fails
    }
    closedir(d);
}

static void create_and_clean_test_directory()
{
    struct stat st = {0};

    if(stat(DT_TCLIB_TEST_DIRECTORY, &st) == -1) {
        mkdir(DT_TCLIB_TEST_DIRECTORY, 0700);
    }
    else {
        clean_directory(DT_TCLIB_TEST_DIRECTORY);
    }
}

static void delete_test_directory()
{
    clean_directory(DT_TCLIB_TEST_DIRECTORY);
    remove(DT_TCLIB_TEST_DIRECTORY);
}

int main()
{
    int number_failed = 0;
    create_and_clean_test_directory();

    Suite *s = suite_create("Database interface testing");
    SRunner *runner = srunner_create(s);

    add_test_cases(s);
    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    delete_test_directory();
    srunner_free(runner);
    return (number_failed == 0) ? 0 : 1;
}

