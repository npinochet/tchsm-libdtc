#ifndef DT_TCLIB_MESSAGES_H_
#define DT_TCLIB_MESSAGES_H_
#include <stdint.h>

enum OP {
    OP_STORE_KEY_PUB,
    OP_STORE_KEY_REQ,
    OP_STORE_KEY_RES,

    //Keep this at the end.
    OP_MAX
};

struct store_key_pub{
    char *server_id;
    char *key_id;
};

struct store_key_req {
    // Indicates if the key_id is accepted or not.
    uint8_t server_id_accepted;
};

struct store_key_res {
    void *key_share;
    void *meta_info;
    char *key_id;
};

union command_args {
    struct store_key_pub store_key_pub;
    struct store_key_req store_key_req;
    struct store_key_res store_key_res;
};

struct op_req{
    uint16_t version;
    enum OP op;
    union command_args *args;
};

/**
 * Serialize the operation_request structure into bytes that can safely be send
 * through the network.
 *
 * Args:
 *  operation_request: Struct to be serialized.
 *  output: The serialization will be pointed by *output. The memory is owned
 *  by the caller, after using the data should call free.
 *
 * Returns:
 *  Size of the operation_request's serialization. It's safe to read at most
 *  this value from *output. If it returns 0, the operation failed and output
 *  isn't modified.
 **/
size_t serialize_op_req(const struct op_req *operation_request, char **output);

/**
 * Rebuild the op_req struct from a previous serialization.
 *
 * Args:
 *  operation_request: Buffer with the serialization.
 *  size: Size of the serialization buffer, should be the size returned by
 *  serialize, there is no need to include a NULL byte at the end.
 *
 * Returns:
 *  The op_req struct serialized in operation_request, the caller own the
 *  memory, so it's his responsibility to call free. NULL is returned on
 *  failure.
 **/
struct op_req *unserialize_op_req(const char *operation_request, size_t size);

/**
 * Recursively free the memory in operation_request. Intended to be used when
 * operation_request was built at unserialize_op_req.
 *
 * Args:
 *  operation_request: Struct to be freed.
 *
 * Returns:
 *  0 on success, 1 otherwise.
 **/
int delete_op_req(struct op_req *operation_request);


#ifdef UNIT_TEST
#include <check.h>

TCase *get_dt_tclib_messages_c_test_case(void);

#endif
#endif
