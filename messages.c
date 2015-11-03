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
        LOG(LOG_LVL_CRIT, "Key \"server_id\" does not exists.");
        goto err_exit;
    }
    ret->server_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.");
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
        LOG(LOG_LVL_CRIT, "Key \"key_id_accepted\" does not exists.");
        goto err_exit;
    }

    ret->key_id_accepted = (uint8_t) json_object_get_int(temp);

    if(!json_object_object_get_ex(in, "key_id", &temp)){
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.");
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    return ret_union;

err_exit:
    free(ret_union);
    return NULL;
}

static int delete_store_key_req(union command_args *data) {
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

    free(serialized_key_metainfo);
    free(serialized_key_share);

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
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.");
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "meta_info", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"metainfo\" does not exists.");
        free((void *) ret->key_id);
        goto err_exit;
    }
    ret->meta_info = tc_deserialize_key_metainfo(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "key_share", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"key_share\" does not exists.");
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

static struct json_object *serialize_delete_key_share_pub(
        const union command_args *args_u, uint16_t version){

    const struct delete_key_share_pub *delete_key_share =
            &args_u->delete_key_share_pub;
    struct json_object *ret;

    if(version != 1)
        return NULL;

    ret = json_object_new_object();

    json_object_object_add(ret, "key_id",
                           json_object_new_string(delete_key_share->key_id));
    return ret;
}

static union command_args *unserialize_delete_key_share_pub(
        struct json_object *in, uint16_t version) {

    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct delete_key_share_pub *ret = &ret_union->delete_key_share_pub;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.");
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    return ret_union;

err_exit:
    free(ret);
    return NULL;
}

static int delete_delete_key_share_pub(union command_args *data) {
    struct delete_key_share_pub *delete_key_share = &data->delete_key_share_pub;
    free((void *)delete_key_share->key_id);
    free(data);
    return 0;
}

static struct json_object *serialize_delete_key_share_req(
        const union command_args *args_u, uint16_t version){

    const struct delete_key_share_req *delete_key_share =
            &args_u->delete_key_share_req;
    struct json_object *ret;

    if(version != 1)
        return NULL;

    ret = json_object_new_object();

    json_object_object_add(
            ret, "deleted",
            json_object_new_int(delete_key_share->deleted));

    json_object_object_add(ret, "key_id",
                           json_object_new_string(delete_key_share->key_id));
    return ret;
}

static union command_args *unserialize_delete_key_share_req(
        struct json_object *in, uint16_t version) {

    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct delete_key_share_req *ret = &ret_union->delete_key_share_req;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.")
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "deleted", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"deleted\" does not exists.");
        goto err_exit;
    }
    ret->deleted = (uint8_t) json_object_get_int(temp);

    return ret_union;

err_exit:
    free(ret);
    return NULL;
}

static int delete_delete_key_share_req(union command_args *data){
    struct delete_key_share_req *delete_key_share =
        &data->delete_key_share_req;
    free((void *)delete_key_share->key_id);
    free(data);
    return 0;
}

static struct json_object *serialize_sign_pub(
        const union command_args *args_u, uint16_t version){

    const struct sign_pub *sign_pub = &args_u->sign_pub;
    struct json_object *ret;

    if(version != 1)
        return NULL;
    bytes_t b = {.data=(void *)sign_pub->message,
                 .data_len=sign_pub->msg_len};

    const char *serialized_msg = tc_bytes_b64(&b);

    ret = json_object_new_object();

    json_object_object_add(ret, "signing_id",
                           json_object_new_string(sign_pub->signing_id));
    json_object_object_add(ret, "key_id",
                           json_object_new_string(sign_pub->key_id));
    json_object_object_add(ret, "message",
                           json_object_new_string(serialized_msg));

    free((void *)serialized_msg);
    return ret;
}

static union command_args *unserialize_sign_pub(
        struct json_object *in, uint16_t version) {

    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct sign_pub *ret = &ret_union->sign_pub;
    bytes_t *msg;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.")
        goto err_exit;
    }
    ret->key_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "signing_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"signing_id\" does not exists.")
        free((void *)ret->key_id);
        goto err_exit;
    }
    ret->signing_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "message", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"message\" does not exists.")
        free((void *)ret->key_id);
        free((void *)ret->signing_id);
        goto err_exit;
    }

    msg = tc_b64_bytes(json_object_get_string(temp));
    ret->message = (uint8_t *)msg->data;
    ret->msg_len = msg->data_len;

    free(msg);

    return ret_union;

err_exit:
    free(ret);
    return NULL;
}

static int delete_sign_pub(union command_args *data){
    struct sign_pub *sign_pub = &data->sign_pub;
    free((void *)sign_pub->key_id);
    free((void *)sign_pub->signing_id);
    free((void *)sign_pub->message);
    free(data);
    return 0;
}

static struct json_object *serialize_sign_req(
        const union command_args *args_u, uint16_t version){

    const struct sign_req *sign_req = &args_u->sign_req;
    struct json_object *ret;
    const char *serialized_signature;

    if(version != 1)
        return NULL;

    ret = json_object_new_object();

    serialized_signature = tc_serialize_signature_share(sign_req->signature);
    if(!serialized_signature) {
        LOG(LOG_LVL_ERRO, "Failed serializing signature share")
        return NULL;
    }

    json_object_object_add(ret, "status_code",
                           json_object_new_int(sign_req->status_code));
    json_object_object_add(ret, "signing_id",
                           json_object_new_string(sign_req->signing_id));

    json_object_object_add(ret, "signature",
                           json_object_new_string(serialized_signature));
    free((void *)serialized_signature);
    return ret;
}

static union command_args *unserialize_sign_req(
        struct json_object *in, uint16_t version) {

    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct sign_req *ret = &ret_union->sign_req;

    if(version != 1)
        goto err_exit;

    if(!json_object_object_get_ex(in, "status_code", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"status_code\" does not exists.");
        goto err_exit;
    }
    ret->status_code = (uint8_t) json_object_get_int(temp);

    if(!json_object_object_get_ex(in, "signing_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"signing_id\" does not exists.")
        goto err_exit;
    }
    ret->signing_id = strdup(json_object_get_string(temp));

    if(!json_object_object_get_ex(in, "signature", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"signature\" does not exists.")
        free((void *)ret->signing_id);
        goto err_exit;
    }

    ret->signature = tc_deserialize_signature_share(
                                            json_object_get_string(temp));
    if(!ret->signature) {
        LOG(LOG_LVL_CRIT, "Unable to deserialize signature share")
        free((void *)ret->signing_id);
        goto err_exit;
    }
    return ret_union;

err_exit:
    free(ret);
    return NULL;
}

static int delete_sign_req(union command_args *data){
    struct sign_req *sign_req = &data->sign_req;
    free((void *)sign_req->signing_id);
    if(sign_req->signature)
        tc_clear_signature_share((signature_share_t *)sign_req->signature);
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
    {serialize_store_key_pub, serialize_store_key_req, serialize_store_key_res,
     serialize_delete_key_share_pub, serialize_delete_key_share_req,
     serialize_sign_pub, serialize_sign_req};

static union command_args *(*const unserialize_funcs[OP_MAX])(
        struct json_object *in, uint16_t version) =
    {unserialize_store_key_pub,
     unserialize_store_key_req,
     unserialize_store_key_res,
     unserialize_delete_key_share_pub,
     unserialize_delete_key_share_req,
     unserialize_sign_pub,
     unserialize_sign_req};

static int (*delete_funcs[OP_MAX])(union command_args *data) =
    {delete_store_key_pub, delete_store_key_req, delete_store_key_res,
     delete_delete_key_share_pub, delete_delete_key_share_req,
     delete_sign_pub, delete_sign_req};

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
        LOG(LOG_LVL_CRIT, "Version %" PRIu16 " not supported.\n", version);
        goto err_exit;
    }
    if(operation >= OP_MAX) {
        LOG(LOG_LVL_CRIT, "Operation %d not supported.", operation)
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
        LOG(LOG_LVL_CRIT, "BUG(mem leak): JSON reference error, not freed.");
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
        LOG(LOG_LVL_CRIT, "unserialize_op_req: Invalid input.");
        goto err_exit;
    }

    if(!json_object_object_get_ex(parsed_json, "op", &temp_json)){
        LOG(LOG_LVL_CRIT, "Key \"op\" does not exists.");
        goto err_exit;
    }
    ret->op = (int) json_object_get_int(temp_json);

    if(!json_object_object_get_ex(parsed_json, "version", &temp_json)){
        LOG(LOG_LVL_CRIT, "Key \"version\" does not exists.");
        goto err_exit;
    }
    temp_uint32 = json_object_get_int(temp_json);
    if(temp_uint32 > UINT16_MAX) {
        LOG(LOG_LVL_CRIT, "Version (%" PRIu32 ") not valid.", temp_uint32);
        goto err_exit;
    }
    ret->version = (uint16_t) temp_uint32;

    // TODO refactor this into a method?
    if(ret->op >= OP_MAX) {
        LOG(LOG_LVL_CRIT, "Operation %d not supported.", ret->op)
        goto err_exit;
    }

    if(!json_object_object_get_ex(parsed_json, "args", &temp_json)){
        LOG(LOG_LVL_CRIT, "Key \"args\" does not exists.");
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
        LOG(LOG_LVL_CRIT, "Version %" PRIu16 " not supported.",
            operation_request->version);
        return 1;
    }
    if(operation_request->op >= OP_MAX) {
        LOG(LOG_LVL_CRIT, "Operation %d not supported.",operation_request->op);
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

START_TEST(serialize_unserialize_delete_key_share_pub) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.delete_key_share_pub.key_id = TEST_KEY_ID;
    operation_request.version = 1;
    operation_request.op = OP_DELETE_KEY_SHARE_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);

    ck_assert_str_eq(unserialized_op_req->args->delete_key_share_pub.key_id,
                     com_args.delete_key_share_pub.key_id);

    free(output);
    delete_op_req(unserialized_op_req);

}
END_TEST

START_TEST(serialize_unserialize_delete_key_share_req) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.delete_key_share_req.deleted = 3;
    com_args.delete_key_share_req.key_id = "key_id";
    operation_request.version = 1;
    operation_request.op = OP_DELETE_KEY_SHARE_REQ;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);
    ck_assert_int_eq(unserialized_op_req->args->delete_key_share_req.deleted,
                     com_args.delete_key_share_req.deleted);
    ck_assert_str_eq(unserialized_op_req->args->delete_key_share_req.key_id,
                     com_args.delete_key_share_req.key_id);

    free(output);
    delete_op_req(unserialized_op_req);

}
END_TEST

START_TEST(serialize_unserialize_sign_pub) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.sign_pub.signing_id = "signing_id";
    com_args.sign_pub.key_id = "key_id";
    com_args.sign_pub.message = (uint8_t *) "me\0ssage";
    com_args.sign_pub.msg_len = 8;

    operation_request.version = 1;
    operation_request.op = OP_SIGN_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);

    ck_assert_int_eq(unserialized_op_req->args->sign_pub.msg_len,
                     com_args.sign_pub.msg_len);
    ck_assert_str_eq(unserialized_op_req->args->sign_pub.signing_id,
                     com_args.sign_pub.signing_id);
    ck_assert_int_eq(0,
                     memcmp(unserialized_op_req->args->sign_pub.message,
                            com_args.sign_pub.message,
                            com_args.sign_pub.msg_len));
    ck_assert_str_eq(unserialized_op_req->args->sign_pub.key_id,
                     com_args.sign_pub.key_id);

    free(output);
    delete_op_req(unserialized_op_req);
}
END_TEST

START_TEST(serialize_unserialize_sign_req) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;
    const char *got_serialized_ss;

    // Any signature share serialized.
    const char *serialized_ss =
            "AAEAAQAAAEAeWX/lZTXD6a90gwgVkatm4JLdVaKubn/hNuqknpdpVEjSlRWBadv1Md"
            "RZgFGACEFkF2qLomJm+4uZJ1q1I9/AAAAAIG8PfhTzPBMCuPaQB9R09LpWlQk5ENzZ"
            "Lf8GXT9PpboLAAAAf7P1XBhE6oWQ5dp4JEm+wxHfL+1b+q245K59tvcHbin5VDMbPU"
            "yFYIZX3Bj/k5LhPtPJOwXLhVLNJuDsRhfrwX21DR53u9vxk1ZidxPde0hdhTpJBhJX"
            "LPgJbZHwUMafr+O0vDNSPPyxyZV/BAbGLs7rW93r6aW/bBzeNOnMqaU=";
    const signature_share_t *sig =
                            tc_deserialize_signature_share(serialized_ss);
    ck_assert_ptr_ne(NULL, (void *)sig);

    com_args.sign_req.status_code = 3;
    com_args.sign_req.signing_id = "signing_id";
    com_args.sign_req.signature = sig;

    operation_request.version = 1;
    operation_request.op = OP_SIGN_REQ;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);

    ck_assert_int_eq(unserialized_op_req->args->sign_req.status_code,
                     com_args.sign_req.status_code);
    ck_assert_str_eq(unserialized_op_req->args->sign_req.signing_id,
                     com_args.sign_req.signing_id);

    got_serialized_ss = tc_serialize_signature_share(
                            unserialized_op_req->args->sign_req.signature);
    ck_assert_str_eq(got_serialized_ss, serialized_ss);

    free((void *)got_serialized_ss);
    tc_clear_signature_share((signature_share_t *) sig);
    free(output);
    delete_op_req(unserialized_op_req);

}
END_TEST

START_TEST(serialize_unserialized_sign) {
    // Test the complete stack of serialization/unserialization involved during
    // the store and sign process.

    size_t bit_size = 512;
    uint16_t nodes_cant = 5;
    uint16_t threshold = 3;
    const char *key_id = "key_";
    const char *msg = "12345";
    const char *signing_id = "id";
    int i;
    char *stored_msgs[nodes_cant];
    size_t stored_msgs_size[nodes_cant];
    char *sign_req_msgs[nodes_cant];
    size_t sign_req_msgs_size[nodes_cant];
    const signature_share_t *signatures[nodes_cant];
    char *pub_msg;
    size_t pub_msg_size;
    bytes_t doc = {.data=(void *)msg,
                   .data_len=5};
    bytes_t *prep_doc, *to_sign_doc, *final_signature;
    signature_share_t *signature;

    struct op_req op_store_key_res, op_sign_pub, op_sign_req;
    struct op_req *rcvd_store_key, *rcvd_sign_pub, *rcvd_sign_req;
    struct store_key_res store_key_res;
    struct sign_pub sign_pub;
    struct sign_req sign_req;

    op_store_key_res.version = op_sign_pub.version = op_sign_req.version = 1;
    op_store_key_res.op = OP_STORE_KEY_RES;
    op_sign_pub.op = OP_SIGN_PUB;
    op_sign_req.op = OP_SIGN_REQ;

    op_store_key_res.args = (union command_args *)&store_key_res;
    op_sign_pub.args = (union command_args *)&sign_pub;
    op_sign_req.args = (union command_args *)&sign_req;

    store_key_res.key_id = key_id;
    sign_req.status_code = 0;
    sign_req.signing_id = signing_id;

    key_metainfo_t *metainfo;
    key_share_t **key_shares;

    key_shares = tc_generate_keys(&metainfo, bit_size, threshold, nodes_cant);
    ck_assert_ptr_ne(NULL, (void *)key_shares);

    prep_doc = tc_prepare_document(&doc, TC_SHA256, metainfo);

    //Store key
    store_key_res.meta_info = metainfo;
    for(i = 0; i < nodes_cant; i++) {
        store_key_res.key_share = key_shares[i];
        stored_msgs_size[i] = serialize_op_req(&op_store_key_res,
                                               &stored_msgs[i]);
        ck_assert_int_ne(0, stored_msgs_size[i]);
        ck_assert_ptr_ne(NULL, (void *)stored_msgs[i]);
    }

    //Sign request
    sign_pub.signing_id = signing_id;
    sign_pub.key_id = key_id;
    sign_pub.message = (uint8_t *)prep_doc->data;
    sign_pub.msg_len = prep_doc->data_len;
    pub_msg_size = serialize_op_req(&op_sign_pub, (void *)&pub_msg);
    ck_assert_int_ne(0, pub_msg_size);

    //Sign
    rcvd_sign_pub = unserialize_op_req(pub_msg, pub_msg_size);
    ck_assert_ptr_ne(NULL, (void *) rcvd_sign_pub);
    to_sign_doc = tc_init_bytes((void *)rcvd_sign_pub->args->sign_pub.message,
                                rcvd_sign_pub->args->sign_pub.msg_len);
    for(i = 0; i < nodes_cant; i++) {
        rcvd_store_key = unserialize_op_req(stored_msgs[i], stored_msgs_size[i]);
        ck_assert_ptr_ne(NULL, (void *)rcvd_store_key);
        signature = tc_node_sign(rcvd_store_key->args->store_key_res.key_share,
                                 to_sign_doc,
                                 rcvd_store_key->args->store_key_res.meta_info);
        ck_assert_int_eq(
                1, tc_verify_signature(
                        signature, to_sign_doc,
                        rcvd_store_key->args->store_key_res.meta_info));
        sign_req.signature = signature;
        sign_req_msgs_size[i] = serialize_op_req(&op_sign_req,
                                                 &sign_req_msgs[i]);
        tc_clear_signature_share(signature);
        delete_op_req(rcvd_store_key);
    }

    for(i = 0; i < nodes_cant; i++) {
        rcvd_sign_req = unserialize_op_req(sign_req_msgs[i],
                                           sign_req_msgs_size[i]);

        ck_assert_ptr_ne(NULL, (void *)rcvd_sign_req);
        ck_assert_int_eq(
                1, tc_verify_signature(
                        rcvd_sign_req->args->sign_req.signature, prep_doc,
                        metainfo));
        signatures[i] = rcvd_sign_req->args->sign_req.signature;

        rcvd_sign_req->args->sign_req.signature = NULL;
        delete_op_req(rcvd_sign_req);
    }

    final_signature = tc_join_signatures(signatures, prep_doc, metainfo);

    ck_assert_int_eq(
            1, tc_rsa_verify(final_signature, &doc, metainfo, TC_SHA256));

    for(i = 0; i < nodes_cant; i++) {
        free((void *)stored_msgs[i]);
        free((void *)sign_req_msgs[i]);
        tc_clear_signature_share((signature_share_t *)signatures[i]);
    }
    tc_clear_bytes(prep_doc);
    free(to_sign_doc);
    tc_clear_bytes(final_signature);
    tc_clear_key_shares(key_shares, metainfo);
    tc_clear_key_metainfo(metainfo);
    delete_op_req(rcvd_sign_pub);
    free(pub_msg);
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

    tcase_add_test(test_case, serialize_unserialize_delete_key_share_pub);
    tcase_add_test(test_case, serialize_unserialize_delete_key_share_req);

    tcase_add_test(test_case, serialize_unserialize_sign_pub);
    tcase_add_test(test_case, serialize_unserialize_sign_req);

    tcase_add_test(test_case, serialize_unserialized_sign);

    return test_case;
}

//TODO(fmontoto) Test store_key_res serialization

#endif
