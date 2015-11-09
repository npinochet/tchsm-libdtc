#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "logger/logger.h"

#include "dtc.h"

int main(int argc, char **argv)
{
    int ret_val = 0;
    key_metainfo_t *info = NULL;
    char *char_msg = "My msg";
    bytes_t *signature;

    logger_init_stream(stderr);
    LOG(LOG_LVL_NOTI, "Logger started for %s", argv[0]);

    dtc_ctx_t *ctx = dtc_init(NULL, &ret_val);

    printf("Init ret: %d\n", ret_val);
    if(ret_val != DTC_ERR_NONE)
        return 1;

    sleep(1);

    ret_val = dtc_generate_key_shares(ctx, "hola_id", 512, 2, 2, &info);
    printf("Generate: %d\n", ret_val);
    if(ret_val != DTC_ERR_NONE) {
        printf("Destroy: %d\n", dtc_destroy(ctx));
        return 1;
    }

    bytes_t *msg = tc_init_bytes((void *)char_msg, strlen(char_msg));
    bytes_t *prep_msg = tc_prepare_document(msg, TC_SHA256, info);
    printf("Before signing\n");
    sleep(5);

    ret_val = dtc_sign(ctx, info, "hola_id", prep_msg, &signature);
    printf("Sign: %d\n", ret_val);

    if(ret_val == DTC_ERR_NONE) {
        printf("Verify: %d\n", tc_rsa_verify(signature, msg, info, TC_SHA256));
        tc_clear_bytes(signature);
    }

    tc_clear_key_metainfo(info);
    tc_clear_bytes(prep_msg);
    free(msg);

    dtc_delete_key_shares(ctx, "hola_id");

    printf("Destroy: %d\n", dtc_destroy(ctx));


    return 0;
}
