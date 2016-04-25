#ifndef DT_TCLIB_DATABASE_H_
#define DT_TCLIB_DATABASE_H_

#include <sqlite3.h>

#include "tc.h"
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
 *  Creates a new temporal token for the router socket of the instance with the
 *  public key provided iff the key is already in the database.
 *
 *  @param db Active database connection.
 *  @param instance_public_key Public key of the instance for the one we will
 *      get a new token.
 *  @param output The token will be pointed by *output if the execution is
 *      successful. *output will point to dynamic memory, the caller is
 *      responsible for freeing the memory on a successful call.
 *
 *  @return DTC_ERR_NONE on success, a proper positive error code if something
 *      fails or -1 if the instance is not stored in the database.
 */
int db_get_new_router_token(database_t *db, const char *instance_public_key,
                            char **output);

/**
 *  Creates a new temporal token for the pub socket of the instance with the
 *  public key provided iff the key is already in the database.
 *
 *  @param db Active database connection.
 *  @param instance_public_key Public key of the instance for the one we will
 *      get a new token.
 *  @param output The token will be pointed by *output if the execution is
 *      successful. *output will point to dynamic memory, the caller is
 *      responsible for freeing the memory on a successful call.
 *
 *  @return DTC_ERR_NONE on success, a proper positive error code if something
 *      fails or -1 if the instance is not stored in the database.
 */
int db_get_new_pub_token(database_t *db, const char *instance_public_key,
                         char **output);

/**
 * Retrieve from the database the current token for the router socket of the
 * instance specified by instance_id. This value is undefined before a call to
 * db_get_new_temp_token, since the token is generated there.
 *
 * @param db Active database connection.
 * @param instance_id Id of the instance.
 * @param output On success, the current token will be pointed by *output.
 *      In this case, the caller has to free the memory.
 *
 * @return DTC_ERR_NONE on successs, a proper positive error code if something
 *      fails or -1 if the instance is not stored in the database.
 **/
int db_get_router_token(database_t *db, const char *instance_id, char **output);

/**
 * Retrieve from the database the current token for the pub socket of the
 * instance specified by instance_id. This value is undefined before a call to
 * db_get_new_temp_token, since the token is generated there.
 *
 * @param db Active database connection.
 * @param instance_id Id of the instance.
 * @param output On success, the current token will be pointed by *output.
 *      In this case, the caller has to free the memory.
 *
 * @return DTC_ERR_NONE on successs, a proper positive error code if something
 *      fails or -1 if the instance is not stored in the database.
 **/
int db_get_pub_token(database_t *db, const char *instance_id, char **output);

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
//TODO Delete this? Seems like it will not be used.
int db_get_instance_id(database_t *db, const char *public_key, char **output);

int db_get_instance_id_from_pub_token(database_t *db, const char *pub_token,
                                    char **output);

int db_get_instance_id_from_router_token(database_t *db, const char *router_token,
                                       char **output);
/**
 * Add a new instance to the DB, this is stored in a temporal table until
 * db_update_instances is called and the old instances are replaced by the new
 * ones. After a call to db_update_instances this method will fail.
 *
 * @param db Active database connection.
 * @param id instance id.
 * @param public_key Public key of the instance.
 *
 * @return DTC_ERR_NONE on success, a proper error message otherwise.
 */
int db_add_new_instance(database_t *db, const char *id, const char *public_key);

/**
 * Remove all the instances in the database that where not added with
 * db_add_new_instance, update the ones that existed and add the ones that where
 * not present previously and where added by db_add_new_instance.
 *
 * @return DTC_ERR_NONE on success, a proper error message otherwise.
 */
int db_update_instances(database_t *db);

/**
 * Check in the database if the key_id provided is available for the instance.
 *
 * @param db Active database connection.
 * @param instance_id Specify the instance for the one we want to check the key_id.
 * @param key_id key_id to check availability for.
 *
 * @return 1 if the key_id wasn't previously associated to the instance, 0 if it's
 *      already used and 2 if an error occurred.
 */
int db_is_key_id_available(database_t *db, const char *instance_id,
                           const char *key_id);

/**
 * Retrieve a stored key.
 *
 * @param db Active database connection.
 * @param instance_id Specify the instance for the one we want to retrieve the key.
 * @param key_id Id of the key to retrieve.
 * @param key_share On succes *key_share will point to the key_share, this is
 *      dynamic memory, should be freed by the caller. On error this parameter
 *      won't be modified.
 * @param key_metainfo On success *key_metainfo will point to the key_metainfo,
 *      this is dynamic memory, should be freed by the caller. On error this
 *      parameter won't be modified.
 *
 * @return DTC_ERR_NONE on success, -1 if the key wasn't present and a positive
 *      error code otherwise.
 */
int db_get_key(database_t *db, const char *instance_id, const char *key_id,
               char **key_share, char **key_metainfo);
/**
 * Insert a new key in the database, a key is the metainfo of the key plus
 * the key share that belongs to thi node.
 *
 * @param db Active database connection.
 * @param instance_id The instance asking to store the key.
 * @param key_id The id to store the key with.
 * @param metainfo The key metainfo.
 * @param key_share The share of the key for this node.
 *
 * @return DTC_ERR_NONE if the key was successfully inserted, -1 if it couldn't
 *      be inserted and a positive error code on error.
 */
int db_store_key(database_t *db, const char *instance_id, const char *key_id,
                 const char *metainfo, const char *key_share);

/**
 * Delete the specified key from the database.
 *
 * @param db Active database connection.
 * @param instance_id The instance requesting to delete the key.
 * @param key_id The id of the key to delete.
 *
 * @return DTC_ERR_NONE if the key was successfully deleted, -1 if it wasn't
 *      present, a positive error code on error.
 */
int db_delete_key(database_t *db, const char *instance_id, const char *key_id);

/**
 * Close and release the memory of a connection, after this call the connection
 * is closed and the behavior of using it is undefined.
 *
 * @param db Active connection to close.
 */
void db_close_and_free_connection(database_t *db);

// For testing purpose only, DO NOT USE IT.
void *get_sqlite3_conn(database_t *database_conn);
int create_tables(database_t *db);
#endif // DT_TCLIB_DATABASE_H_
