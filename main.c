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
    if(ret_val != DTC_ERR_NONE)
        return 1;

    bytes_t *msg = tc_init_bytes((void *)char_msg, strlen(char_msg));

    ret_val = dtc_sign(ctx, info, "hola_id", msg, &signature);
    printf("%d\n", ret_val);

    tc_clear_key_metainfo(info);

    dtc_delete_key_shares(ctx, "hola_id");

    printf("Destroy: %d\n", dtc_destroy(ctx));

    return 0;
}
