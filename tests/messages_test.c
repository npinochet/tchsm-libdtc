#include <stdlib.h>

#include <check.h>

#include "messages.h"

char *TEST_INSTANCE_ID = "instance_01";
char *TEST_KEY_ID = "key_id_01";
char *TEST_CONNECTION_ID = "213";

START_TEST(serialize_op_req_store_key_pub_simple) {
    char *output;
    size_t ret;
    struct op_req operation_request;

    union command_args com_args;
    com_args.store_key_pub.connection_id = TEST_CONNECTION_ID;
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

START_TEST(serialize_unserialize_op_req_corrupted) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.store_key_pub.connection_id = TEST_CONNECTION_ID;
    com_args.store_key_pub.key_id = TEST_KEY_ID;
    operation_request.version = 1;
    operation_request.op = OP_STORE_KEY_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    output[strlen(output)/2] = '\0';
    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req == NULL);
    free(output);
    delete_op_req(unserialized_op_req);

}
END_TEST

START_TEST(serialize_unserialize_op_req) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.store_key_pub.connection_id = TEST_CONNECTION_ID;
    com_args.store_key_pub.key_id = TEST_KEY_ID;
    operation_request.version = 1;
    operation_request.op = OP_STORE_KEY_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);
    ck_assert_str_eq(unserialized_op_req->args->store_key_pub.connection_id,
                     com_args.store_key_pub.connection_id);

    ck_assert_str_eq(unserialized_op_req->args->store_key_pub.key_id,
                     com_args.store_key_pub.key_id);

    free(output);
    delete_op_req(unserialized_op_req);

}
END_TEST

START_TEST(serialize_unserialize_delete_key_share_pub_corrupted) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.delete_key_share_pub.key_id = TEST_KEY_ID;
    com_args.delete_key_share_pub.connection_id = TEST_CONNECTION_ID;
    operation_request.version = 1;
    operation_request.op = OP_DELETE_KEY_SHARE_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);
    output[strlen(output)/2] = '\0';

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req == NULL);

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
    com_args.delete_key_share_pub.connection_id = TEST_CONNECTION_ID;
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

START_TEST(serialize_unserialize_delete_key_share_req_corrupted) {
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
    output[strlen(output)/2] = '\0';
    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req == NULL);

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

START_TEST(serialize_unserialize_store_key_ack_corrupted) {
    char *key_id = "14OUASDH";
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.store_key_ack.status = 4;
    com_args.store_key_ack.key_id = key_id;

    operation_request.op = OP_STORE_KEY_ACK;
    operation_request.args = &com_args;
    operation_request.version = 1;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);
    output[strlen(output) / 2] = '\0';

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req == NULL);

    free(output);
}
END_TEST

START_TEST(serialize_unserialize_store_key_ack) {
    char *key_id = "14OUASDH";
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.store_key_ack.status = 4;
    com_args.store_key_ack.key_id = key_id;

    operation_request.op = OP_STORE_KEY_ACK;
    operation_request.args = &com_args;
    operation_request.version = 1;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req->version == operation_request.version);
    ck_assert(unserialized_op_req->op == operation_request.op);
    ck_assert_int_eq(unserialized_op_req->args->store_key_ack.status,
                     com_args.store_key_ack.status);
    ck_assert_str_eq(unserialized_op_req->args->store_key_ack.key_id,
                     com_args.store_key_ack.key_id);

    free(output);
    delete_op_req(unserialized_op_req);
}
END_TEST

START_TEST(serialize_unserialize_sign_pub_corrupted) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

    com_args.sign_pub.signing_id = "signing_id";
    com_args.sign_pub.key_id = "key_id";
    com_args.sign_pub.message = (uint8_t *) "me\0ssage";
    com_args.sign_pub.msg_len = 8;
    com_args.sign_pub.connection_id = TEST_CONNECTION_ID;

    operation_request.version = 1;
    operation_request.op = OP_SIGN_PUB;
    operation_request.args = &com_args;

    ret = serialize_op_req(&operation_request, &output);
    ck_assert(ret > 0);
    output[strlen(output)/2] = '\0';

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req == NULL);

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
    com_args.sign_pub.connection_id = TEST_CONNECTION_ID;

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
    ck_assert_str_eq(unserialized_op_req->args->sign_pub.connection_id,
                     com_args.sign_pub.connection_id);
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

START_TEST(serialize_unserialize_sign_req_corrupted) {
    char *output;
    size_t ret;
    struct op_req operation_request;
    struct op_req *unserialized_op_req;
    union command_args com_args;

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
    output[ strlen(output) / 2] = '\0';

    unserialized_op_req = unserialize_op_req(output, ret);

    ck_assert(unserialized_op_req == NULL);


    tc_clear_signature_share((signature_share_t *) sig);
    free(output);

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

    key_shares = tc_generate_keys(&metainfo, bit_size, threshold, nodes_cant,
                                  NULL);
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
    sign_pub.connection_id = TEST_CONNECTION_ID;
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

TCase* get_test_case(){
    TCase *test_case = tcase_create("messages");
    tcase_set_timeout(test_case, 10);

    tcase_add_test(test_case, serialize_op_req_store_key_pub_simple);
    tcase_add_test(test_case, serialize_op_req_store_key_pub_wrong_version);

    tcase_add_test(test_case, serialize_unserialize_op_req_corrupted);
    tcase_add_test(test_case, serialize_unserialize_op_req);

    tcase_add_test(test_case, serialize_unserialize_store_key_ack_corrupted);
    tcase_add_test(test_case, serialize_unserialize_store_key_ack);

    tcase_add_test(test_case, serialize_unserialize_delete_key_share_pub_corrupted);
    tcase_add_test(test_case, serialize_unserialize_delete_key_share_pub);

    tcase_add_test(test_case, serialize_unserialize_delete_key_share_req_corrupted);
    tcase_add_test(test_case, serialize_unserialize_delete_key_share_req);

    tcase_add_test(test_case, serialize_unserialize_sign_pub_corrupted);
    tcase_add_test(test_case, serialize_unserialize_sign_pub);

    tcase_add_test(test_case, serialize_unserialize_sign_req_corrupted);
    tcase_add_test(test_case, serialize_unserialize_sign_req);

    tcase_add_test(test_case, serialize_unserialized_sign);

    return test_case;
}

//TODO(fmontoto) Test store_key_res serialization

int main()
{
    int number_failed = 0;

    Suite *s = suite_create("Struct testing");

    SRunner *runner = srunner_create(s);

    suite_add_tcase(s, get_test_case());

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);

    return (number_failed == 0) ? 0 :1;
}

