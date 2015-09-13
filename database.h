#ifndef DT_TCLIB_DATABASE_H_
#define DT_TCLIB_DATABASE_H_

#include <sqlite3.h>

#include "database.h"

struct database_conn;
typedef struct database_conn database_t;

/**
 * Initialize a connection with the database in path.
 * Do not use the connection from different threads, make one connectino
 * per thread.
 *
 * @param path Location of the file with the database or path where to
 *      store the databse if it does not exits.
 *
 * @return A connection to the database to be used in the next methods,
 *      to release the connection and free the memory the user must call
 *      db_close_and_free_connection. On error NULL is returned.
 */
database_t *db_init_connection(const char *path);

/**
 * Check if the key is a public key of an authorized master or not.
 *
 * @param db Active database connection.
 * @param key Key to check in the databse.
 *
 * @return 1 if key is an authorized key, 0 if it is not and -1 on
 *      error.
 */
int db_is_an_authorized_key(database_t *db, const char *key);

/**
 *  Creates a new temporal token for the server with the public key provided if
 *  the key is already in the database.
 *
 *  @param db Active database connection.
 *  @param server_public_key Public key of the server for the one we will
 *      a new token.
 *  @param output The token will be pointed by *output if the execution is
 *      successful. *output will point to dynamic memory, the caller is
 *      responsible for freeing the memory on a successful call.
 *
 *  @return DTC_ERR_NONE on success, a proper positive error code if something
 *      fails or -1 if the server is not stored in the database.
 */
int db_get_new_temp_token(database_t *db, const char *server_public_key,
                          const char **output);

/**
 *  Retrieve from the database the current token for the server specified by
 * server_id.
 *
 * @param db Active database connection.
 * @param server_id Id of the server.
 * @param output On success, the current token will be pointed by *output.
 *      In this case, the caller has to free the memory.
 *
 * @return DTC_ERR_NONE on successs, a proper positive error code if something
 *      fails or -1 if the server is not stored in the database.
 **/
int get_current_token(database_t *db, const char *server_id, char **output);

/**
 * Close and release the memory of a connection, after this call the connection
 * is closed and the behavior of using it is undefined.
 *
 * @param db Active connection to close.
 */
void db_close_and_free_connection(database_t *db);
#endif // DT_TCLIB_DATABASE_H_

#ifdef UNIT_TEST
#include <check.h>

TCase *get_dt_tclib_database_c_test_case(void);

#endif
