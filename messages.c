#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "logger/logger.h"
#include "messages.h"

// TODO(fmontoto) Helper method to check valid versions.

// struct store_key_pub utilities
static struct json_object *serialize_store_key_pub(
        const union command_args *args_u, uint16_t version){

    const struct store_key_pub *store_key_pub = &args_u->store_key_pub;
    struct json_object *ret;

    if(version != 1)
        return NULL;

    ret = json_object_new_object();

    json_object_object_add(ret, "server_id",
                            json_object_new_string(store_key_pub->server_id));
    json_object_object_add(ret, "key_id",
                           json_object_new_string(store_key_pub->key_id));
    return ret;
}

static union command_args *unserialize_store_key_pub(struct json_object *in,
                                                     uint16_t version) {
    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct store_key_pub *ret = &ret_union->store_key_pub;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "server_id", &temp)){
        LOG(LOG_LVL_CRT, "Key \"server_id\" does not exists.");
        goto err_exit;
    }
    ret->server_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRT, "Key \"key_id\" does not exists.");
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    return ret_union;

err_exit:
    free(ret);
    return NULL;
}

int delete_store_key_pub(union command_args *data) {
    struct store_key_pub *store_key_pub = &data->store_key_pub;
    free((void *)store_key_pub->server_id);
    free((void *)store_key_pub->key_id);
    free(data);
    return 0;
}

// struct store_key_req
static struct json_object *serialize_store_key_req(
        const union command_args *args_u, uint16_t version) {
    const struct store_key_req *store_key_req = &args_u->store_key_req;
    struct json_object *ret;

    if(version != 1)
        return NULL;

    ret = json_object_new_object();
    json_object_object_add(
            ret, "key_id_accepted",
            json_object_new_int(store_key_req->key_id_accepted));

    json_object_object_add(
            ret, "key_id", json_object_new_string(store_key_req->key_id));

    return ret;
}

static union command_args *unserialize_store_key_req(struct json_object *in,
                                                     uint16_t version) {
    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct store_key_req *ret = &ret_union->store_key_req;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "key_id_accepted", &temp)) {
        LOG(LOG_LVL_CRT, "Key \"key_id_accepted\" does not exists.");
        goto err_exit;
    }

    ret->key_id_accepted = (uint8_t) json_object_get_int(temp);

    if(!json_object_object_get_ex(in, "key_id", &temp)){
        LOG(LOG_LVL_CRT, "Key \"key_id\" does not exists.");
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    return ret_union;

err_exit:
    free(ret_union);
    return NULL;
}

int delete_store_key_req(union command_args *data) {
    struct store_key_req *store_key_req = &data->store_key_req;
    free((void *)store_key_req->key_id);
    free(data);
    return 0;
}

static struct json_object *serialize_store_key_res(
        const union command_args *args_u, uint16_t version) {
    const struct store_key_res *store_key_res = &args_u->store_key_res;
    struct json_object *ret;
    char *serialized_key_metainfo, *serialized_key_share;

    if(version != 1)
        return NULL;

    serialized_key_metainfo = tc_serialize_key_metainfo(
            store_key_res->meta_info);

    serialized_key_share = tc_serialize_key_share(store_key_res->key_share);

    ret = json_object_new_object();

    json_object_object_add(ret, "key_share",
                           json_object_new_string(serialized_key_share));

    json_object_object_add(ret, "meta_info",
                           json_object_new_string(serialized_key_metainfo));

    json_object_object_add(ret, "key_id",
                           json_object_new_string(store_key_res->key_id));

    return ret;
}

static union command_args *unserialize_store_key_res(struct json_object *in,
                                                     uint16_t version) {
    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct store_key_res *ret = &ret_union->store_key_res;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRT, "Key \"key_id\" does not exists.");
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "meta_info", &temp)) {
        LOG(LOG_LVL_CRT, "Key \"metainfo\" does not exists.");
        free((void *) ret->key_id);
        goto err_exit;
    }
    ret->meta_info = tc_deserialize_key_metainfo(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "key_share", &temp)) {
        LOG(LOG_LVL_CRT, "Key \"key_share\" does not exists.");
        free((void *) ret->key_id);
        tc_clear_key_metainfo(ret->meta_info);
        goto err_exit;
    }
    ret->key_share = tc_deserialize_key_share(json_object_get_string(temp));

    return ret_union;

err_exit:
    free(ret_union);
    return NULL;
}

static int delete_store_key_res(union command_args *data) {
    struct store_key_res *store_key_res = &data->store_key_res;
    free((void *)store_key_res->key_id);
    tc_clear_key_metainfo(store_key_res->meta_info);
    tc_clear_key_share(store_key_res->key_share);
    free(data);
    return 0;
}

// *************************************************************
// ***********************Public API****************************
// *************************************************************

// Arrays with functions to do the serialization/unserialization and deletion.
static struct json_object *(
        *const serialize_funcs[OP_MAX])(const union command_args *data,
                                        uint16_t version) =
    {serialize_store_key_pub, serialize_store_key_req, serialize_store_key_res};

static union command_args *(*const unserialize_funcs[OP_MAX])(
        struct json_object *in, uint16_t version) =
    {unserialize_store_key_pub,
     unserialize_store_key_req,
     unserialize_store_key_res};

static int (*delete_funcs[OP_MAX])(union command_args *data) =
    {delete_store_key_pub, delete_store_key_req, delete_store_key_res};


// *************************************************************
// ***********************Public API****************************
// *************************************************************

size_t serialize_op_req(const struct op_req *operation_request, char **output){
    struct json_object *temp;
    int operation = (int) operation_request->op;
    uint16_t version = operation_request->version;
    const char *temp_char_ptr;
    struct json_object *json_ret = json_object_new_object();
    size_t ret = 0;


    if(version != 1){
        LOG(LOG_LVL_CRT, "Version %" PRIu16 " not supported.\n", version);
        goto err_exit;
    }
    if(operation >= OP_MAX) {
        LOG(LOG_LVL_CRT, "Operation %d not supported.", operation)
        goto err_exit;
    }

    json_object_object_add(json_ret, "op",
                           json_object_new_int(operation_request->op));
    json_object_object_add(json_ret, "version",
                           json_object_new_int(operation_request->version));
    temp = (serialize_funcs[operation])(operation_request->args, version);
    if(!temp)
        goto err_exit;
    json_object_object_add(json_ret, "args", temp);

    // TODO pretty just for testing purposes
    temp_char_ptr =
        json_object_to_json_string_ext(json_ret, JSON_C_TO_STRING_PRETTY);

    // TODO(fmontoto) strdup?
    ret = strlen(temp_char_ptr);
    *output = (char *) malloc(ret * sizeof(char));
    memcpy(*output, temp_char_ptr, ret);
    json_object_put(json_ret);

    return ret;

err_exit:
    if(!json_object_put(json_ret))
        LOG(LOG_LVL_CRT, "BUG(mem leak): JSON reference error, not freed.");
    return 0;

}

struct op_req *unserialize_op_req(const char *operation_request, size_t size){
    struct json_object *temp_json, *parsed_json;
    uint32_t temp_uint32;
    union command_args *temp_args;
    struct op_req *ret = (struct op_req *) malloc(sizeof(struct op_req));
    struct json_tokener *json_tok = json_tokener_new();

    parsed_json = json_tokener_parse_ex(json_tok, operation_request, size);
    json_tokener_free(json_tok);
    if(!parsed_json){
        LOG(LOG_LVL_CRT, "unserialize_op_req: Invalid input.");
        goto err_exit;
    }

    if(!json_object_object_get_ex(parsed_json, "op", &temp_json)){
        LOG(LOG_LVL_CRT, "Key \"op\" does not exists.");
        goto err_exit;
    }
    ret->op = (int) json_object_get_int(temp_json);

    if(!json_object_object_get_ex(parsed_json, "version", &temp_json)){
        LOG(LOG_LVL_CRT, "Key \"version\" does not exists.");
        goto err_exit;
    }
    temp_uint32 = json_object_get_int(temp_json);
    if(temp_uint32 > UINT16_MAX) {
        LOG(LOG_LVL_CRT, "Version (%" PRIu32 ") not valid.", temp_uint32);
        goto err_exit;
    }
    ret->version = (uint16_t) temp_uint32;

    // TODO refactor this into a method?
    if(ret->op >= OP_MAX) {
        LOG(LOG_LVL_CRT, "Operation %d not supported.", ret->op)
        goto err_exit;
    }

    if(!json_object_object_get_ex(parsed_json, "args", &temp_json)){
        LOG(LOG_LVL_CRT, "Key \"args\" does not exists.");
        goto err_exit;
    }
    temp_args = (unserialize_funcs[ret->op])(temp_json, ret->version);
    if(!temp_args)
        goto err_exit;
    ret->args = temp_args;

    json_object_put(parsed_json);

    return ret;

err_exit:
    free(ret);
    return NULL;
}

int delete_op_req(struct op_req *operation_request){
    int ret = 0;
    if(!operation_request)
        return 0;
    if(operation_request->version != 1){
        LOG(LOG_LVL_CRT, "Version %" PRIu16 " not supported.",
            operation_request->version);
        return 1;
    }
    if(operation_request->op >= OP_MAX) {
        LOG(LOG_LVL_CRT, "Operation %d not supported.",operation_request->op);
        return 1;
    }
    ret = (delete_funcs[operation_request->op])(operation_request->args);
    if(ret)
        return 1;
    free(operation_request);
    return 0;
}


#ifdef UNIT_TEST

char *TEST_SERVER_ID = "server_01";
char *TEST_KEY_ID = "key_id_01";

START_TEST(test_serialize_store_key_pub_simple) {
    union command_args args_u;
    struct store_key_pub *store_key_pub = &args_u.store_key_pub;
    struct json_object *temp_json;

    store_key_pub->server_id = TEST_SERVER_ID;
    store_key_pub->key_id = TEST_KEY_ID;

    struct json_object *ret = serialize_store_key_pub(&args_u, 1);

    json_object_object_get_ex(ret, "server_id", &temp_json);
    ck_assert_str_eq(TEST_SERVER_ID, json_object_get_string(temp_json));

    json_object_object_get_ex(ret, "key_id", &temp_json);
    ck_assert_str_eq(TEST_KEY_ID, json_object_get_string(temp_json));

    json_object_put(ret);
}
END_TEST

START_TEST(test_serialize_store_key_pub_wrong_version) {
    union command_args args_u;

    struct json_object *ret = serialize_store_key_pub(&args_u, 2);

    ck_assert_ptr_eq(NULL, ret);

}
END_TEST

START_TEST(unserialize_store_key_pub_simple) {
    union command_args *obtained;
    json_object *input = json_object_new_object();

    json_object_object_add(input, "server_id",
                           json_object_new_string(TEST_SERVER_ID));
    json_object_object_add(input, "key_id",
                           json_object_new_string(TEST_KEY_ID));

    obtained = unserialize_store_key_pub(input, 1);
    ck_assert_str_eq(TEST_SERVER_ID, obtained->store_key_pub.server_id);
    ck_assert_str_eq(TEST_KEY_ID, obtained->store_key_pub.key_id);

    delete_store_key_pub(obtained);
    json_object_put(input);

}
END_TEST

START_TEST(unserialize_store_key_pub_wrong_input) {
    union command_args *obtained;

    json_object *input = json_object_new_object();

    json_object_object_add(input, "server",
                           json_object_new_string(TEST_SERVER_ID));
    obtained = unserialize_store_key_pub(input, 1);
    ck_assert_ptr_eq(NULL, obtained);
    json_object_put(input);
}
END_TEST

START_TEST(serialize_unserialize_store_key_pub) {
    union command_args store_key_pub;
    union command_args *obtained_store_key_pub;
    json_object *json_obj;

    store_key_pub.store_key_pub.server_id = TEST_SERVER_ID;
    store_key_pub.store_key_pub.key_id = TEST_KEY_ID;


    json_obj = serialize_store_key_pub(&store_key_pub, 1);
    obtained_store_key_pub = unserialize_store_key_pub(json_obj, 1);

    ck_assert_str_eq(store_key_pub.store_key_pub.server_id,
                     obtained_store_key_pub->store_key_pub.server_id);
    ck_assert_str_eq(store_key_pub.store_key_pub.key_id,
                     obtained_store_key_pub->store_key_pub.key_id);
    ck_assert_ptr_ne(&store_key_pub, obtained_store_key_pub);

    json_object_put(json_obj);
    delete_store_key_pub(obtained_store_key_pub);
}
END_TEST

START_TEST(serialize_unserialize_store_key_req) {
    union command_args store_key_req;
    union command_args *obtained_store_key_req;
    json_object *json_obj;
    const char *key_id = "key_id";
    const uint8_t key_id_accepted = 2;

    store_key_req.store_key_req.key_id_accepted = key_id_accepted;
    store_key_req.store_key_req.key_id = key_id;

    json_obj = serialize_store_key_req(&store_key_req, 1);
    obtained_store_key_req = unserialize_store_key_req(json_obj, 1);

    ck_assert(key_id_accepted ==
              obtained_store_key_req->store_key_req.key_id_accepted);
    ck_assert_str_eq(key_id, obtained_store_key_req->store_key_req.key_id);

    json_object_put(json_obj);
    delete_store_key_req(obtained_store_key_req);


}
END_TEST

/****************************************************
 * *****************API Testing**********************
 * *************************************************/

START_TEST(serialize_op_req_store_key_pub_simple) {
    char *output;
    size_t ret;
    struct op_req operation_request;

    union command_args com_args;
    com_args.store_key_pub.server_id = TEST_SERVER_ID;
    com_args.store_key_pub.key_id = TEST_KEY_ID;
    operation_request.version = 1;
    operation_request.op = OP_STORE_KEY_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);



    free(output);
}
END_TEST

START_TEST(serialize_op_req_store_key_pub_wrong_version) {
    char *output;
    size_t ret;

    struct op_req operation_request;
    operation_request.version = 5;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret == 0);
}
END_TEST

START_TEST(serialize_unserialize_op_req) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.store_key_pub.server_id = TEST_SERVER_ID;
    com_args.store_key_pub.key_id = TEST_KEY_ID;
    operation_request.version = 1;
    operation_request.op = OP_STORE_KEY_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);
    ck_assert_str_eq(unserialized_op_req->args->store_key_pub.server_id,
                     com_args.store_key_pub.server_id);

    ck_assert_str_eq(unserialized_op_req->args->store_key_pub.key_id,
                     com_args.store_key_pub.key_id);

    free(output);
    delete_op_req(unserialized_op_req);

}
END_TEST

TCase* get_dt_tclib_messages_c_test_case(){
    TCase *test_case = tcase_create("messages_c");

    tcase_add_test(test_case, test_serialize_store_key_pub_simple);
    tcase_add_test(test_case, test_serialize_store_key_pub_wrong_version);

    tcase_add_test(test_case, unserialize_store_key_pub_simple);
    tcase_add_test(test_case, unserialize_store_key_pub_wrong_input);

    tcase_add_test(test_case, serialize_unserialize_store_key_pub);
    tcase_add_test(test_case, serialize_op_req_store_key_pub_simple);

    tcase_add_test(test_case, serialize_unserialize_store_key_req);

    tcase_add_test(test_case, serialize_op_req_store_key_pub_wrong_version);
    tcase_add_test(test_case, serialize_unserialize_op_req);

    return test_case;
}

//TODO(fmontoto) Test store_key_res serialization

#endif
