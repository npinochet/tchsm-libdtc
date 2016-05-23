#include "tc.h"
//#include "../tclib/include/tc_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <botan/hash.h>
#include <botan/lookup.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <iostream>
#include <botan/auto_rng.h>


static const char *_message = "Hello world";
static char *message;
static int key_size = 1024;
static int k = 3;
static int l = 5;

void set_parameters(int argc, char **argv) {

    message = strdup(_message);
#ifndef __CPROVER__
    int opt;
    while ((opt = getopt(argc, argv, "m:k:l:s:")) != -1) {
        switch (opt) {
            case 'm':
                free(message);
                message = strdup(optarg);
                break;
            case 'k':
                k = strtol(optarg, NULL, 10);
                break;
            case 'l':
                l = strtol(optarg, NULL, 10);
                break;
            case 's':
                key_size = strtol(optarg, NULL, 10);
                break;
        }
    }
#endif
}

bytes_t *prepare_doc(bytes_t *doc, key_metainfo_t *metainfo) {
    Botan::EMSA *emsa = Botan::get_emsa("EMSA4(SHA-256)");
    emsa->update(static_cast<Botan::byte *>(doc->data), doc->data_len);

    const public_key_t *tc_pk = tc_key_meta_info_public_key(metainfo);
    Botan::BigInt n((Botan::byte *) tc_pk->n->data, tc_pk->n->data_len);

    Botan::AutoSeeded_RNG rng;
    auto v = emsa->encoding_of(emsa->raw_data(), n.bits()-1, rng);
    bytes_t *rv = tc_init_bytes(malloc(v.size()), v.size());

    std::copy(v.begin(), v.end(), (Botan::byte*)rv->data);
    // std::memcpy(rv->data, v, v.size());
    return rv;
}

bool verify_rsa(bytes_t *doc, bytes_t *signature, const key_metainfo_t *metainfo) {
    const public_key_t *tc_pk = tc_key_meta_info_public_key(metainfo);
    Botan::BigInt n((Botan::byte *) tc_pk->n->data, tc_pk->n->data_len);
    Botan::BigInt e((Botan::byte *) tc_pk->e->data, tc_pk->e->data_len);

    Botan::RSA_PublicKey pk(n, e);
    Botan::PK_Verifier verifier(pk, "EMSA4(SHA-256)");
    verifier.update((Botan::byte*) doc->data, doc->data_len);
    return verifier.check_signature((Botan::byte*)signature->data, signature->data_len);
}


int main(int argc, char **argv) {
    set_parameters(argc, argv);
    char *b64;

    key_metainfo_t *info;
    key_share_t **shares = tc_generate_keys(&info, key_size, k, l, NULL);

    bytes_t *doc = tc_init_bytes(message, strlen(message));

    b64 = tc_bytes_b64(doc);
    printf("Document: %s\n", b64);
    free(b64);

    bytes_t *doc_pkcs1 = prepare_doc(doc, info);

    b64 = tc_bytes_b64(doc_pkcs1);
    printf("Prepared Document: %s\n", b64);
    free(b64);

    signature_share_t *signatures[l];

    for (int i = 0; i < l; i++) {
        signatures[i] = tc_node_sign(shares[i], doc_pkcs1, info);
        int verify = tc_verify_signature(signatures[i], doc_pkcs1, info);
        assert(verify);
    }

    bytes_t *signature = tc_join_signatures((const signature_share_t **) signatures, doc_pkcs1, info);
    bool verify = verify_rsa(doc, signature, info);
    printf("Verify RSA: %d\n", verify);

    b64 = tc_bytes_b64(signature);
    printf("Signature: %s\n", b64);
    free(b64);

    tc_clear_bytes_n(doc, doc_pkcs1, signature, NULL);
    for (int i = 0; i < l; i++) {
        tc_clear_signature_share(signatures[i]);
    }
    tc_clear_key_shares(shares, info);
    tc_clear_key_metainfo(info);
}
