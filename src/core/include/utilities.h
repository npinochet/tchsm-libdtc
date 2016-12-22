#ifndef DT_TCLIB_UTILITIES_H_
#define DT_TCLIB_UTILITIES_H_

#include <libconfig.h>

// TODO document
char *create_identity(const char *instance_id, const char *connection_id);

/**
 * Auxiliary function to read an uint16_t from a config_setting_t, it's read
 * as int64 and then tested if it fit in an uint16_t.
 *
 * @param setting setting to perform the lookup.
 * @param name name of the uint16 in the configuration.
 * @param out on success will point to the value looked for.
 *          On error will not be modified.
 *
 * @return DTC_ERR_NONE on success, a proper error code otherwise.
 **/
int lookup_uint16_conf_element(const config_setting_t *setting,
                               const char *name, uint16_t *out);

/**
 * Auxiliary function to read an string from a config_setting_t and copy it
 * into a new memory chunk to persist after the config_setting_t deletion.
 *
 * @param setting setting to perform the lookup.
 * @param name name of the string in the configuration.
 * @param value the copied string will be stored at *value.
 *          On error will not be modified.
 *
 * @return DTC_ERR_NONE on success, a proper error code otherwise.
 *
 **/
int lookup_string_conf_element(const config_setting_t *setting,
                               const char *name, const char **value);
/**
 * Generate and dump a new uuid into ret.
 *
 * @param ret Should point to at least 37 bytes to store the uuid into.
 *
 * @return ret
 */
char *get_uuid_as_char(char *ret);

/**
 * Call free_func with data as arg.
 *
 * @param data Data to be freed.
 * @param free_func Functio to be called in order to free data.
 */
void free_wrapper(void *data, void *hint);

/**
 * Send a string as zmq msg.
 *
 * @param socket ZMQ socket to send the message through.
 * @param string C String to be send as message.
 *
 * @return Bytes sent.
 */
int s_send(void *socket, const char *string);

/**
 * Send a string as not terminal zmq multipart message.
 *
 * @param socket ZMQ socket to send the message through.
 * @param string C String to be send as message.
 *
 * @return Bytes sent.
 */
int s_sendmore(void *socket, const char *string);

/**
 * Receive a ZMQ string from a zmq_socket and convert it into a C string The
 * function will receive a string with a max len of 255. The string will be
 * truncated if it's larger than 255.
 *
 * @param socket socket to receive from.
 *
 * @return The received string on success or NULL on error. The caller is
 *      responsible for the memory on success and should call free to avoid
 *      memory leaks.
 */
char *s_recv(void *socket);

#endif // DT_TCLIB_UTILTIES_H_
