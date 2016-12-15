#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "logger.h"

#include <include/dtc.h>

char *KEY_HANDLER = "default_handler";

/** Args:
 * 1: path to the config file
 * 2: number of nodes
 * [3]: threshold
 * [4]: key handler
 */
int main(int argc, char **argv)
{
    int ret_val = 0;
    int verify;
    key_metainfo_t *info = NULL;
    char *char_msg = "My msg";
    bytes_t *signature;

    OPEN_LOG(NULL, LOG_CONS | LOG_PERROR, LOG_LOCAL0);
    LOG(LOG_LVL_NOTI, "Logger started for %s", argv[0]);

    dtc_ctx_t *ctx = dtc_init(argv[1], &ret_val);

    printf("Init ret: %d:%s\n", ret_val, dtc_get_error_msg(ret_val));
    if(ret_val != DTC_ERR_NONE)
        return ret_val;

    int number_of_nodes = atoi(argv[2]);
    int threshold = number_of_nodes / 2 + 1;
    if(argc > 3) {
        threshold = atoi(argv[3]);
        if(argc > 4)
            KEY_HANDLER = argv[4];
    }

    ret_val = dtc_generate_key_shares(ctx, KEY_HANDLER, 512, threshold, number_of_nodes, NULL, &info);
    printf("Generate: %d:%s\n", ret_val, dtc_get_error_msg(ret_val));
    if(ret_val != DTC_ERR_NONE) {
        printf("Destroy: %d\n", dtc_destroy(ctx));
        return ret_val;
    }

    bytes_t *msg = tc_init_bytes((void *)char_msg, strlen(char_msg));
    bytes_t *prep_msg = tc_prepare_document(msg, TC_SHA256, info);

    ret_val = dtc_sign(ctx, info, KEY_HANDLER, prep_msg, &signature);
    printf("Sign: %d: %s\n", ret_val, dtc_get_error_msg(ret_val));

    if(ret_val == DTC_ERR_NONE) {
        verify = tc_rsa_verify(signature, msg, info, TC_SHA256);
        printf("Verify: %d\n", verify);
        tc_clear_bytes(signature);
        if(verify != 1) {
            return 1;
        }
    }

    tc_clear_key_metainfo(info);
    tc_clear_bytes(prep_msg);
    free(msg);

    dtc_delete_key_shares(ctx, KEY_HANDLER);

    printf("Destroy: %d\n", dtc_destroy(ctx));


    return ret_val;
}
