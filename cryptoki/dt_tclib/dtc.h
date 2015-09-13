#ifndef DT_TCLIB_DTC_H_
#define DT_TCLIB_DTC_H_

#include "err.h"

struct dtc_ctx;
typedef struct dtc_ctx dtc_ctx_t;

dtc_ctx_t *dtc_init(const char *config_file, int *err);

// TODO Implement and document the API.
int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes,
                            public_key_t **info);

uint8_t *dtc_sign(dtc_ctx_t *ctx, uint32_t key_id, uint8_t *message,
                  size_t msg_len);

void dtc_delete_key_shares(dtc_ctx_t *ctx, uint32_t key_id);

int dtc_destroy(dtc_ctx_t *ctx);

const char *dtc_get_error_msg(int errno);

#endif
