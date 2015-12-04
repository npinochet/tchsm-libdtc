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

static struct json_object *serialize_store_key_ack(
        const union command_args *args_u, uint16_t version)
{

    const struct store_key_ack *store_key_ack = &args_u->store_key_ack;
    struct json_object *ret;

    if(version != 1)
        return NULL;

    ret = json_object_new();

    json_object_object_add(ret, "key_id",
                           json_object_new_string(store_key_ack->key_id));
    json_object_object_add(ret, "status",
                           json_object_new_int(store_key_ack->status));

    return ret;
}

static struct json_object *unserialize_store_key_ack(struct json_object *in,
                                                     uint16_t version)
{
    struct json_object *temp;
    union command_args *ret_union =
        (union command_args *) malloc(sizeof(union command_args));
    struct store_key_ack *ret = &ret_union->store_key_req;

    if(version != 1)
        goto err_exit;

    if(!json_object_get_ex(in, "key_id", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"key_id\" does not exists.")
        goto err_exit;
    }

    ret->key_id = strdup(json_object_get_string(temp));

    if(!json_object_get_ex(in, "status", &temp)) {
        LOG(LOG_LVL_CRIT, "Key \"status\" does not exists.")
        goto err_exit;
    }

    ret->status = (uint8_t) json_object_get_int(temp);

    return ret_union;

err_exit:
    free(ret_union);
    return NULL;
}

static int delete_store_key_ack(union command_args *data)
{
    struct store_key_ack *store_key_ack = &data->store_key_ack;
    free((void *)store_key_ack->ret->key_id);
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
    {
        serialize_store_key_pub,
        serialize_store_key_req,
        serialize_store_key_res,
        serialize_store_key_ack,
        serialize_delete_key_share_pub,
        serialize_delete_key_share_req,
        serialize_sign_pub,
        serialize_sign_req
    };

static union command_args *(*const unserialize_funcs[OP_MAX])(
        struct json_object *in, uint16_t version) =
    {
        unserialize_store_key_pub,
        unserialize_store_key_req,
        unserialize_store_key_res,
        unserialize_store_key_ack,
        unserialize_delete_key_share_pub,
        unserialize_delete_key_share_req,
        unserialize_sign_pub,
        unserialize_sign_req
    };

static int (*delete_funcs[OP_MAX])(union command_args *data) =
    {
        delete_store_key_pub,
        delete_store_key_req,
        delete_store_key_res,
        delete_delete_key_share_pub,
        delete_delete_key_share_req,
        delete_sign_pub,
        delete_sign_req
    };

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
